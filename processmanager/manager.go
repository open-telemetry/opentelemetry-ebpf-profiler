// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package processmanager manages the loading and unloading of information related to processes.
package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/zeebo/xxh3"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/dotnet"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind"
	"go.opentelemetry.io/ebpf-profiler/periodiccaller"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/process/processcontext"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	eim "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const (
	// ELFInfoCacheSize is the maximum size of the LRU cache holding the executables'
	// ELF information. It is exported so other packages (e.g. usdt) can share it.
	ELFInfoCacheSize = 16384

	// TTL of entries in the LRU cache holding the executables' ELF information.
	elfInfoCacheTTL = 6 * time.Hour

	// DefaultFrameCacheSize is the default maximum size of the LRU cache for frames.
	DefaultFrameCacheSize uint32 = 16384
)

// dummyPrefix is the LPM prefix installed to indicate the process is known
var dummyPrefix = lpm.Prefix{Key: 0, Length: 64}

var (
	errSymbolizationNotSupported = errors.New("symbolization not supported")
	// errPIDGone indicates that a process is no longer managed by the process manager.
	errPIDGone = errors.New("interpreter process gone")
)

// Config contains the dependencies and options used to create a ProcessManager.
type Config struct {
	InterpretersConfig    interpreterconfig.Config
	MonitorInterval       time.Duration
	ExecutableUnloadDelay time.Duration
	EbpfHandler           pmebpf.EbpfHandler
	TraceReporter         reporter.TraceReporter
	ExecutableReporter    reporter.ExecutableReporter
	StackDeltaProvider    nativeunwind.StackDeltaProvider
	KernelSymbolizer      *kallsyms.Symbolizer
	FrameCacheSize        uint32
	FilterErrorFrames     bool
	IncludeEnvVars        libpf.Set[string]
	ProcessMetaEnrichers  []process.MetaEnricher
	// Origins assigns origin IDs and their metadata and hooks; nil creates
	// an empty registry.
	Origins *OriginRegistry
}

// New creates a new ProcessManager which is responsible for keeping track of loading
// and unloading of symbols for processes.
func New(ctx context.Context, cfg Config) (*ProcessManager, error) {
	if cfg.Origins == nil {
		cfg.Origins = &OriginRegistry{}
	}
	if cfg.ExecutableReporter == nil {
		cfg.ExecutableReporter = executableReporterStub{}
	}
	if cfg.TraceReporter == nil {
		cfg.TraceReporter = traceReporterStub{}
	}
	if cfg.FrameCacheSize == 0 {
		cfg.FrameCacheSize = DefaultFrameCacheSize
	}

	elfInfoCache, err := lru.New[util.OnDiskFileIdentifier, elfInfo](ELFInfoCacheSize,
		util.OnDiskFileIdentifier.Hash32)
	if err != nil {
		return nil, fmt.Errorf("unable to create elfInfoCache: %v", err)
	}
	elfInfoCache.SetLifetime(elfInfoCacheTTL)

	frameCache, err := lru.New[frameCacheKey, libpf.Frames](cfg.FrameCacheSize, hashFrameCacheKey)
	if err != nil {
		return nil, fmt.Errorf("unable to create frameCache: %v", err)
	}

	em, err := eim.NewExecutableInfoManager(cfg.StackDeltaProvider, cfg.EbpfHandler, cfg.InterpretersConfig)
	if err != nil {
		return nil, fmt.Errorf("unable to create ExecutableInfoManager: %v", err)
	}

	periodiccaller.Start(ctx, cfg.ExecutableUnloadDelay, func() {
		err := em.CleanupUnused(cfg.ExecutableUnloadDelay)
		if err != nil {
			log.Errorf("Failed to cleanup unused executables: %v", err)
		}
	})

	interpreters := make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance)
	var ks kallsyms.Resolver
	if cfg.KernelSymbolizer != nil {
		ks = cfg.KernelSymbolizer
	}

	metaEnrichers := make([]process.MetaEnricher, 0, len(cfg.ProcessMetaEnrichers)+2)
	// Cloned: the enricher closure outlives New, and the caller owns cfg.
	metaEnrichers = append(metaEnrichers, process.NewEnvVarsEnricher(
		maps.Clone(cfg.IncludeEnvVars), processcontext.EnvVarSet()))

	selfContainerEnricher, err := process.NewSelfContainerIDEnricher()
	if err != nil {
		log.Debugf("Failed to detect self container ID via inode: %v", err)
	} else {
		metaEnrichers = append(metaEnrichers, selfContainerEnricher)
	}
	metaEnrichers = append(metaEnrichers, cfg.ProcessMetaEnrichers...)

	pm := &ProcessManager{
		interpreterTracerEnabled: em.NumInterpreterLoaders() > 0,
		eim:                      em,
		interpreters:             interpreters,
		exitEvents:               make(map[libpf.PID]times.KTime),
		pidToProcessInfo:         make(map[libpf.PID]*processInfo),
		ebpf:                     cfg.EbpfHandler,
		elfInfoCache:             elfInfoCache,
		frameCache:               frameCache,
		traceReporter:            cfg.TraceReporter,
		exeReporter:              cfg.ExecutableReporter,
		kernelSymbols:            ks,
		metricsAddSlice:          metrics.AddSlice,
		filterErrorFrames:        cfg.FilterErrorFrames,
		metaEnrichers:            metaEnrichers,
		attachedProbes:           make(map[libpf.PID]map[ProbeAttacher]libpf.Void),
		origins:                  cfg.Origins,
		tracePool:                newTraceEventPool(),
	}

	collectInterpreterMetrics(ctx, pm, cfg.MonitorInterval)

	return pm, nil
}

// metricSummaryToSlice creates a metrics.Metric slice from a map of metric IDs to values.
func metricSummaryToSlice(summary metrics.Summary) []metrics.Metric {
	result := make([]metrics.Metric, 0, len(summary))
	for mID, mVal := range summary {
		result = append(result, metrics.Metric{ID: mID, Value: mVal})
	}
	return result
}

// updateMetricSummary gets the metrics from the provided interpreter instance and updates the
// provided summary by aggregating the new metrics into the summary.
// The caller is responsible to hold the lock on the interpreter.Instance to avoid race conditions.
func updateMetricSummary(ii interpreter.Instance, summary metrics.Summary) error {
	instanceMetrics, err := ii.GetAndResetMetrics()
	// Update metrics even if there was an error, because it's possible ii is a MultiInstance
	// and some of the instances may have returned metrics.
	for _, metric := range instanceMetrics {
		summary[metric.ID] += metric.Value
	}

	return err
}

// collectInterpreterMetrics starts a goroutine that periodically fetches and reports interpreter
// metrics.
func collectInterpreterMetrics(ctx context.Context, pm *ProcessManager,
	monitorInterval time.Duration,
) {
	if !metrics.Enabled() {
		return
	}
	periodiccaller.Start(ctx, monitorInterval, func() {
		pm.mu.RLock()
		defer pm.mu.RUnlock()

		summary := make(metrics.Summary)

		for pid := range pm.interpreters {
			for addr, ii := range pm.interpreters[pid] {
				if err := updateMetricSummary(ii, summary); err != nil {
					log.Errorf("Failed to get/reset metrics for PID %d at 0x%x: %v",
						pid, addr, err)
				}
			}
		}

		summary[metrics.IDHashmapPidPageToMappingInfo] = metrics.MetricValue(pm.pidPageToMappingInfoSize)

		summary[metrics.IDELFInfoCacheHit] = metrics.MetricValue(pm.elfInfoCacheHit.Swap(0))
		summary[metrics.IDELFInfoCacheMiss] = metrics.MetricValue(pm.elfInfoCacheMiss.Swap(0))

		summary[metrics.IDTraceCacheHit] = metrics.MetricValue(pm.frameCacheHit.Swap(0))
		summary[metrics.IDTraceCacheMiss] = metrics.MetricValue(pm.frameCacheMiss.Swap(0))

		summary[metrics.IDErrProcNotExist] = metrics.MetricValue(pm.mappingStats.errProcNotExist.Swap(0))
		summary[metrics.IDErrProcESRCH] = metrics.MetricValue(pm.mappingStats.errProcESRCH.Swap(0))
		summary[metrics.IDErrProcPerm] = metrics.MetricValue(pm.mappingStats.errProcPerm.Swap(0))
		summary[metrics.IDNumProcAttempts] = metrics.MetricValue(pm.mappingStats.numProcAttempts.Swap(0))
		summary[metrics.IDMaxProcParseUsec] = metrics.MetricValue(pm.mappingStats.maxProcParseUsec.Swap(0))
		summary[metrics.IDTotalProcParseUsec] = metrics.MetricValue(pm.mappingStats.totalProcParseUsec.Swap(0))
		summary[metrics.IDErrProcParse] = metrics.MetricValue(pm.mappingStats.numProcParseErrors.Swap(0))

		summary.Add(dotnet.GetAndResetMetrics())
		summary.Add(processcontext.GetAndResetMetrics())
		summary.Add(pm.ebpf.CollectMetrics())

		pm.eim.UpdateMetricSummary(summary)
		pm.metricsAddSlice(metricSummaryToSlice(summary))
		pm.metricsAddSlice(pm.customLabels.getAndResetMetrics())
		pm.metricsAddSlice(pm.threadLabels.getAndResetMetrics())
	})
}

func (pm *ProcessManager) Close() {
}

func (pm *ProcessManager) symbolizeFrame(pid libpf.PID, data []uint64, frames *libpf.Frames, mapping libpf.FrameMapping) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.interpreters[pid]) == 0 {
		return errPIDGone
	}

	for _, instance := range pm.interpreters[pid] {
		if err := instance.Symbolize(data, frames, mapping); err != nil {
			if errors.Is(err, interpreter.ErrMismatchInterpreterType) {
				// The interpreter type of instance did not match the type of frame.
				// So continue with the next interpreter instance for this PID.
				continue
			}
			return err
		}
		return nil
	}

	return fmt.Errorf("no matching interpreter instance (of len %d): %w",
		len(pm.interpreters[pid]), errSymbolizationNotSupported)
}

func (pm *ProcessManager) appendKernelFrames(addrs []uint64, dst *libpf.Frames) (uint64, uint64) {
	var cacheHit, cacheMiss uint64

	snapshot := pm.kernelSymbols.Snapshot()
	for _, addr := range addrs {
		address := libpf.Address(addr)
		// Kernel/module symbols are the common case. BPF JIT addresses do not
		// overlap module ranges, so cache probe order does not change
		// ResolveAddress precedence.
		if cached, ok := pm.frameCache.Get(kernelFrameCacheKey(address, snapshot.KernelGeneration())); ok {
			cacheHit++
			*dst = append(*dst, cached...)
			continue
		}
		if cached, ok := pm.frameCache.Get(kernelFrameCacheKey(address, snapshot.BPFGeneration())); ok {
			cacheHit++
			*dst = append(*dst, cached...)
			continue
		}

		resolution, resolved := snapshot.ResolveAddress(address)
		frame, cacheable := symbolizeKernelFrame(address, resolution)
		if resolved && cacheable {
			cacheMiss++
			pm.frameCache.Add(kernelFrameCacheKey(address, resolution.Generation), libpf.Frames{frame})
		}

		*dst = append(*dst, frame)
	}

	return cacheHit, cacheMiss
}

// convertFrame converts one host Frame to one or more libpf.Frames. It returns true
// if the converted frame data should be cached.
func (pm *ProcessManager) convertFrame(pid libpf.PID, ef libpf.EbpfFrame, dst *libpf.Frames) bool {
	switch ef.Type().Interpreter() {
	case libpf.UnknownInterp, libpf.Kernel:
		log.Errorf("Unexpected frame type 0x%02X (neither error nor usermode frame)",
			uint8(ef.Type()))
	case libpf.Native:
		fileID := host.FileID(ef.Variable(0))
		address := libpf.Address(ef.Data())

		// Locate mapping info for the frame.
		mapping := pm.findMappingForTrace(pid, fileID, address)

		// Attempt symbolization of native frames. It is best effort and
		// provides non-symbolized frames if no native symbolizer is active.
		if err := pm.symbolizeFrame(pid, ef, dst, mapping); err == nil {
			return true
		}

		// The BPF code classifies whether an address is a return address or not.
		// Return addresses are where execution resumes when returning to the stack
		// frame and point to the **next instruction** after the call instruction
		// that produced the frame.
		//
		// For these return addresses we subtract 1 from the address in order to
		// make it point into the call that precedes it: the instruction at the
		// return address may already be part of whatever code follows after the
		// call, and we want the return addresses to resolve to the call itself
		// during symbolization.
		//
		// Optimally we'd subtract the size of the call instruction here instead
		// of doing `- 1`, but disassembling backwards is quite difficult for
		// variable length instruction sets like X86.
		if ef.Flags().ReturnAddress() {
			address--
		}
		dst.Append(&libpf.Frame{
			Type:            ef.Type(),
			AddressOrLineno: libpf.AddressOrLineno(address),
			Mapping:         mapping,
		})
		return mapping.Valid()
	default:
		err := pm.symbolizeFrame(pid, ef, dst, libpf.FrameMapping{})
		if err == nil {
			return true
		}
		log.Debugf("symbolization failed for PID %d, frame type %d: %v",
			pid, ef.Type(), err)
		dst.Append(&libpf.Frame{Type: ef.Type()})
	}
	return false
}

func hashFrameCacheKey(fk frameCacheKey) uint32 {
	return uint32(xxh3.Hash(pfunsafe.FromPointer(&fk)))
}

// HandleTrace is the drop point for a raw trace_events ring buffer record:
// copied, validated, decoded, dispatched to the origin's hooks, symbolized
// and reported.
//
// A returned error indicates a layout-breaking record; the caller should
// stop processing traces.
func (pm *ProcessManager) HandleTrace(raw []byte) error {
	if len(raw) > traceRecordMaxSize {
		return fmt.Errorf("%d > %d: %w", len(raw), traceRecordMaxSize, ErrRecordUnexpectedSize)
	}

	e := pm.tracePool.Get().(*traceEvent)
	*e = traceEvent{}
	e.recordLen = copy(e.rawBytes(), raw)
	// Validate the copy, so validation and decoding always see the same bytes.
	if err := validateRecord(e.rawBytes()[:e.recordLen]); err != nil {
		pm.tracePool.Put(e)
		return err
	}

	pm.processTrace(e)
	return nil
}

// processTrace decodes, dispatches and symbolizes a pooled trace event.
func (pm *ProcessManager) processTrace(e *traceEvent) {
	if err := pm.decodeTrace(e); err != nil {
		log.Warnf("unexpected error handling trace: %v", err)
		pm.tracePool.Put(e)
		return
	}
	if ktime := times.KTime(e.KTime); ktime > pm.maxSeenKTime {
		pm.maxSeenKTime = ktime
	}

	entry := pm.origins.Lookup(e.Origin)
	if entry == nil {
		log.Warnf("dropping trace with unknown origin %d", e.Origin)
		pm.tracePool.Put(e)
		return
	}

	// The trace context aliases the pooled event.
	ctx := &TraceContext{
		Origin:        e.Origin,
		PID:           e.PID,
		TID:           e.TID,
		KTime:         times.KTime(e.KTime),
		Comm:          e.Comm,
		ContextValues: e.ContextValues,
	}
	if !entry.Hooks.PreHandleTrace(ctx) {
		pm.tracePool.Put(e)
		return
	}

	trace := pm.handleDecodedTrace(e, entry.Meta)
	pm.tracePool.Put(e)

	entry.Hooks.PostHandleTrace(ctx, trace)
}

// handleDecodedTrace processes and reports the given decoded trace event.
// Process metadata is looked up here rather than at trace-receive time; if
// the process already exited, the trace is reported without enrichment.
// Not re-entrant: frameCache is not synced.
func (pm *ProcessManager) handleDecodedTrace(e *traceEvent, profileType *samples.TypeMetadata) *libpf.Trace {
	procMeta, resourceAttrs := pm.metaForPID(e.PID)
	meta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(times.KTime(e.KTime).UnixNano()),
		Comm:           e.Comm,
		PID:            e.PID,
		TID:            e.TID,
		CPU:            e.CpuID,
		ExecutablePath: procMeta.Executable,
		ContainerID:    procMeta.ContainerID,
		ProfileType:    profileType,
		ContextValues:  e.ContextValues,
		EnvVars:        procMeta.EnvVariables,
		ResourceAttrs:  resourceAttrs,
		TraceID:        e.TraceID,
		SpanID:         e.SpanID,
		ExtraMeta:      procMeta.ExtraMeta,
	}

	pid := e.PID
	trace := &libpf.Trace{
		Frames:       make(libpf.Frames, 0, len(e.KernelFrames)+int(e.NumFrames)),
		CustomLabels: e.CustomLabels,
	}

	cacheMiss := uint64(0)
	cacheHit := uint64(0)

	if len(e.KernelFrames) > 0 {
		hits, misses := pm.appendKernelFrames(e.KernelFrames, &trace.Frames)
		cacheHit += hits
		cacheMiss += misses
	}

	for frames := libpf.EbpfFrame(e.FrameData); len(frames) > 0; frames = frames[frames.Length():] {
		frame := frames[:frames.Length()]
		if frame.Flags().Error() {
			if !pm.filterErrorFrames {
				trace.Frames.Append(&libpf.Frame{
					Type:            frame.Type().Error(),
					AddressOrLineno: libpf.AddressOrLineno(frame.Data()),
				})
			}
			continue
		}

		oldLen := len(trace.Frames)
		key := frameCacheKey{}
		if frame.Flags().PIDSpecific() {
			key.pid = pid
		}
		copy(key.data[:], frame)
		if cached, ok := pm.frameCache.Get(key); ok {
			// Fast path
			cacheHit++
			trace.Frames = append(trace.Frames, cached...)
		} else {
			// Slow path: convert trace.
			if pm.convertFrame(pid, frame, &trace.Frames) {
				cacheMiss++
				pm.frameCache.Add(key, slices.Clone(trace.Frames[oldLen:len(trace.Frames)]))
			}
		}
	}
	if cacheMiss != 0 {
		pm.frameCacheMiss.Add(cacheMiss)
	}
	if cacheHit != 0 {
		pm.frameCacheHit.Add(cacheHit)
	}
	pm.mu.RLock()
	// Release resources that were used to symbolize this stack.
	for _, instance := range pm.interpreters[pid] {
		if err := instance.ReleaseResources(); err != nil {
			log.Warnf("Failed to release resources for %d: %v", pid, err)
		}
	}
	pm.mu.RUnlock()

	if err := pm.traceReporter.ReportTraceEvent(trace, meta); err != nil {
		log.Errorf("Failed to report trace event: %v", err)
	}

	return trace
}
