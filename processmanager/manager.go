// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package processmanager manages the loading and unloading of information related to processes.
package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"context"
	"errors"
	"fmt"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/tracer/types"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/apmint"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/periodiccaller"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpf"
	eim "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const (
	// lruFileIDCacheSize is the LRU size for caching 64-bit and 128-bit file IDs.
	// This should reflect the number of hot file IDs that are seen often in a trace.
	lruFileIDCacheSize = 32768

	// Maximum size of the LRU cache holding the executables' ELF information.
	elfInfoCacheSize = 16384

	// TTL of entries in the LRU cache holding the executables' ELF information.
	elfInfoCacheTTL = 6 * time.Hour
)

var (
	// dummyPrefix is the LPM prefix installed to indicate the process is known
	dummyPrefix = lpm.Prefix{Key: 0, Length: 64}
)

var (
	errSymbolizationNotSupported = errors.New("symbolization not supported")
	// errUnknownMapping indicates that the memory mapping is not known to
	// the process manager.
	errUnknownMapping = errors.New("unknown memory mapping")
	// errUnknownPID indicates that the process is not known to the process manager.
	errUnknownPID = errors.New("unknown process")
)

// New creates a new ProcessManager which is responsible for keeping track of loading
// and unloading of symbols for processes.
//
// Three external interfaces are used to access the processes and related resources: ebpf,
// fileIDMapper and symbolReporter. Specify nil for fileIDMapper to use the default
// implementation.
func New(ctx context.Context, includeTracers types.IncludedTracers, monitorInterval time.Duration,
	ebpf pmebpf.EbpfHandler, fileIDMapper FileIDMapper, symbolReporter reporter.SymbolReporter,
	sdp nativeunwind.StackDeltaProvider, filterErrorFrames bool,
	collectCustomLabels bool, includeEnvVars libpf.Set[string]) (*ProcessManager, error) {
	if fileIDMapper == nil {
		var err error
		fileIDMapper, err = newFileIDMapper(lruFileIDCacheSize)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize file ID mapping: %v", err)
		}
	}

	elfInfoCache, err := lru.New[util.OnDiskFileIdentifier, elfInfo](elfInfoCacheSize,
		util.OnDiskFileIdentifier.Hash32)
	if err != nil {
		return nil, fmt.Errorf("unable to create elfInfoCache: %v", err)
	}
	elfInfoCache.SetLifetime(elfInfoCacheTTL)

	em, err := eim.NewExecutableInfoManager(sdp, ebpf, includeTracers, collectCustomLabels)
	if err != nil {
		return nil, fmt.Errorf("unable to create ExecutableInfoManager: %v", err)
	}

	interpreters := make(map[libpf.PID]map[util.OnDiskFileIdentifier]interpreter.Instance)

	pm := &ProcessManager{
		interpreterTracerEnabled: em.NumInterpreterLoaders() > 0,
		eim:                      em,
		interpreters:             interpreters,
		exitEvents:               make(map[libpf.PID]times.KTime),
		pidToProcessInfo:         make(map[libpf.PID]*processInfo),
		ebpf:                     ebpf,
		FileIDMapper:             fileIDMapper,
		elfInfoCache:             elfInfoCache,
		reporter:                 symbolReporter,
		metricsAddSlice:          metrics.AddSlice,
		filterErrorFrames:        filterErrorFrames,
		includeEnvVars:           includeEnvVars,
	}

	collectInterpreterMetrics(ctx, pm, monitorInterval)

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

// updateMetricSummary gets the metrics from the provided interpreter instance and updaates the
// provided summary by aggregating the new metrics into the summary.
// The caller is responsible to hold the lock on the interpreter.Instance to avoid race conditions.
func updateMetricSummary(ii interpreter.Instance, summary metrics.Summary) error {
	instanceMetrics, err := ii.GetAndResetMetrics()
	if err != nil {
		return err
	}

	for _, metric := range instanceMetrics {
		summary[metric.ID] += metric.Value
	}

	return nil
}

// collectInterpreterMetrics starts a goroutine that periodically fetches and reports interpreter
// metrics.
func collectInterpreterMetrics(ctx context.Context, pm *ProcessManager,
	monitorInterval time.Duration) {
	periodiccaller.Start(ctx, monitorInterval, func() {
		pm.mu.RLock()
		defer pm.mu.RUnlock()

		summary := make(map[metrics.MetricID]metrics.MetricValue)

		for pid := range pm.interpreters {
			for addr := range pm.interpreters[pid] {
				if err := updateMetricSummary(pm.interpreters[pid][addr], summary); err != nil {
					log.Errorf("Failed to get/reset metrics for PID %d at 0x%x: %v",
						pid, addr, err)
				}
			}
		}

		summary[metrics.IDHashmapPidPageToMappingInfo] =
			metrics.MetricValue(pm.pidPageToMappingInfoSize)

		summary[metrics.IDELFInfoCacheHit] =
			metrics.MetricValue(pm.elfInfoCacheHit.Swap(0))
		summary[metrics.IDELFInfoCacheMiss] =
			metrics.MetricValue(pm.elfInfoCacheMiss.Swap(0))

		summary[metrics.IDErrProcNotExist] =
			metrics.MetricValue(pm.mappingStats.errProcNotExist.Swap(0))
		summary[metrics.IDErrProcESRCH] =
			metrics.MetricValue(pm.mappingStats.errProcESRCH.Swap(0))
		summary[metrics.IDErrProcPerm] =
			metrics.MetricValue(pm.mappingStats.errProcPerm.Swap(0))
		summary[metrics.IDNumProcAttempts] =
			metrics.MetricValue(pm.mappingStats.numProcAttempts.Swap(0))
		summary[metrics.IDMaxProcParseUsec] =
			metrics.MetricValue(pm.mappingStats.maxProcParseUsec.Swap(0))
		summary[metrics.IDTotalProcParseUsec] =
			metrics.MetricValue(pm.mappingStats.totalProcParseUsec.Swap(0))
		summary[metrics.IDErrProcParse] =
			metrics.MetricValue(pm.mappingStats.numProcParseErrors.Swap(0))

		mapsMetrics := pm.ebpf.CollectMetrics()
		for _, metric := range mapsMetrics {
			summary[metric.ID] = metric.Value
		}

		pm.eim.UpdateMetricSummary(summary)
		pm.metricsAddSlice(metricSummaryToSlice(summary))
	})
}

func (pm *ProcessManager) Close() {
}

func (pm *ProcessManager) symbolizeFrame(frame int, trace *host.Trace,
	newTrace *libpf.Trace) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if len(pm.interpreters[trace.PID]) == 0 {
		return errors.New("interpreter process gone")
	}

	for _, instance := range pm.interpreters[trace.PID] {
		if err := instance.Symbolize(pm.reporter, &trace.Frames[frame], newTrace); err != nil {
			if errors.Is(err, interpreter.ErrMismatchInterpreterType) {
				// The interpreter type of instance did not match the type of frame.
				// So continue with the next interpreter instance for this PID.
				continue
			}
			return fmt.Errorf("symbolization failed: %w", err)
		}
		return nil
	}

	return fmt.Errorf("no matching interpreter instance (of len %d): %w",
		len(pm.interpreters[trace.PID]), errSymbolizationNotSupported)
}

func (pm *ProcessManager) ConvertTrace(trace *host.Trace) (newTrace *libpf.Trace, err error) {
	traceLen := len(trace.Frames)

	newTrace = &libpf.Trace{
		Files:        make([]libpf.FileID, 0, traceLen),
		Linenos:      make([]libpf.AddressOrLineno, 0, traceLen),
		FrameTypes:   make([]libpf.FrameType, 0, traceLen),
		CustomLabels: trace.CustomLabels,
	}

	for i := 0; i < traceLen; i++ {
		frame := &trace.Frames[i]

		if frame.Type.IsError() {
			if !pm.filterErrorFrames {
				newTrace.AppendFrame(frame.Type, libpf.UnsymbolizedFileID, frame.Lineno)
			}
			continue
		}

		switch frame.Type.Interpreter() {
		case libpf.UnknownInterp:
			log.Errorf("Unexpected frame type 0x%02X (neither error nor interpreter frame)",
				uint8(frame.Type))
		case libpf.Native, libpf.Kernel:
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
			relativeRIP := frame.Lineno
			if frame.ReturnAddress {
				relativeRIP--
			}

			// Locate mapping info for the frame.
			var mappingStart, mappingEnd libpf.Address
			var fileOffset uint64
			if frame.Type.Interpreter() == libpf.Native {
				if mapping, ok := pm.findMappingForTrace(trace.PID, frame.File, frame.Lineno); ok {
					mappingStart = mapping.Vaddr - libpf.Address(mapping.Bias)
					mappingEnd = mappingStart + libpf.Address(mapping.Length)
					fileOffset = mapping.FileOffset
				}
			}

			fileID, ok := pm.FileIDMapper.Get(frame.File)
			if !ok {
				log.Debugf(
					"file ID lookup failed for PID %d, frame %d/%d, frame type %d",
					trace.PID, i, traceLen, frame.Type)

				newTrace.AppendFrameFull(frame.Type, libpf.UnsymbolizedFileID,
					libpf.AddressOrLineno(0), mappingStart, mappingEnd, fileOffset)
				continue
			}

			newTrace.AppendFrameFull(frame.Type, fileID,
				relativeRIP, mappingStart, mappingEnd, fileOffset)
		default:
			err := pm.symbolizeFrame(i, trace, newTrace)
			if err != nil {
				if errors.Is(err, interpreter.ErrLJRestart) {
					return nil, err
				}
				log.Debugf(
					"symbolization failed for PID %d, frame %d/%d, frame type %d: %v",
					trace.PID, i, traceLen, frame.Type, err)

				newTrace.AppendFrame(frame.Type, libpf.UnsymbolizedFileID, libpf.AddressOrLineno(0))
			}
		}
	}
	newTrace.Hash = traceutil.HashTrace(newTrace)
	return newTrace, nil
}

func (pm *ProcessManager) MaybeNotifyAPMAgent(
	rawTrace *host.Trace, umTraceHash libpf.TraceHash, count uint16) string {
	pidInterp, ok := pm.interpreters[rawTrace.PID]
	if !ok {
		return ""
	}

	var serviceName string
	for _, mapping := range pidInterp {
		if apm, ok := mapping.(*apmint.Instance); ok {
			apm.NotifyAPMAgent(rawTrace.PID, rawTrace, umTraceHash, count)

			if serviceName != "" {
				log.Warnf("Overwriting APM service name from '%s' to '%s' for PID %d",
					serviceName,
					apm.APMServiceName(),
					rawTrace.PID)
			}
			// It's pretty unusual to have more than one APM agent in a
			// single process, but in case there is, just pick the last one.
			serviceName = apm.APMServiceName()
		}
	}

	return serviceName
}

// AddSynthIntervalData adds synthetic stack deltas to the manager. This is useful for cases where
// populating the information via the stack delta provider isn't viable, for example because the
// `.eh_frame` section for a binary is broken. If `AddSynthIntervalData` was called for a given
// file ID, the stack delta provider will not be consulted and the manually added stack deltas take
// precedence.
func (pm *ProcessManager) AddSynthIntervalData(fileID host.FileID,
	data sdtypes.IntervalData) error {
	return pm.eim.AddSynthIntervalData(fileID, data)
}
