/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package processmanager manages the loading and unloading of information related to processes.
package processmanager

import (
	"context"
	"errors"
	"fmt"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/interpreter"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind"
	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
	"github.com/elastic/otel-profiling-agent/libpf/periodiccaller"
	"github.com/elastic/otel-profiling-agent/libpf/traceutil"
	"github.com/elastic/otel-profiling-agent/lpm"
	"github.com/elastic/otel-profiling-agent/metrics"
	pmebpf "github.com/elastic/otel-profiling-agent/processmanager/ebpf"
	eim "github.com/elastic/otel-profiling-agent/processmanager/execinfomanager"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/times"
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
// Four external interfaces are used to access the processes and related resources: ebpf,
// fileIDMapper, opener and reportFrameMetadata. Specify 'nil' for these interfaces to use
// the default implementation.
func New(ctx context.Context, includeTracers []bool, monitorInterval time.Duration,
	ebpf pmebpf.EbpfHandler, fileIDMapper FileIDMapper, symbolReporter reporter.SymbolReporter,
	sdp nativeunwind.StackDeltaProvider, filterErrorFrames bool) (*ProcessManager, error) {
	if fileIDMapper == nil {
		var err error
		fileIDMapper, err = newFileIDMapper(lruFileIDCacheSize)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize file ID mapping: %v", err)
		}
	}

	elfInfoCache, err := lru.New[libpf.OnDiskFileIdentifier, elfInfo](elfInfoCacheSize,
		libpf.OnDiskFileIdentifier.Hash32)
	if err != nil {
		return nil, fmt.Errorf("unable to create elfInfoCache: %v", err)
	}
	elfInfoCache.SetLifetime(elfInfoCacheTTL)

	em := eim.NewExecutableInfoManager(sdp, ebpf, includeTracers)

	interpreters := make(map[libpf.PID]map[libpf.OnDiskFileIdentifier]interpreter.Instance)

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
		return fmt.Errorf("interpreter process gone")
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

func (pm *ProcessManager) ConvertTrace(trace *host.Trace) (newTrace *libpf.Trace) {
	traceLen := len(trace.Frames)

	newTrace = &libpf.Trace{
		Files:      make([]libpf.FileID, 0, traceLen),
		Linenos:    make([]libpf.AddressOrLineno, 0, traceLen),
		FrameTypes: make([]libpf.FrameType, 0, traceLen),
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
			// When unwinding stacks, the address is obtained from the stack
			// which contains pointer to the *next* instruction to be executed.
			//
			// For all kernel frames, the kernel unwinder will always produce
			// a frame in which the RIP is after a call instruction (it hides the top
			// frames that leads to the unwinder itself).
			//
			// For leaf user mode frames (without kernel frames) the RIP from
			// our unwinder is good as is, and must not be altered because the
			// previous instruction address is unknown -- we might have just
			// executed a jump or a call that got us to the address found in
			// these frames.
			//
			// For other user mode frames we are at the next instruction after a
			// call. And often the next instruction is already part of the next
			// source code line's debug info areas. So we need to fixup the non-top
			// frames so that we get source code lines pointing to the call instruction.
			// We would ideally wish to subtract the size of the instruction from
			// the return address we retrieved - but the size of calls can vary
			// (indirect calls etc.). If, on the other hand, we subtract 1 from
			// the address, we ensure that we fall into the range of addresses
			// associated with that function call in the debug information.
			//
			// The unwinder will produce stack traces like the following:
			//
			// Frame 0:
			// bla %reg           <- address of frame 0
			// retq
			//
			// Frame 1:
			// call <function>
			// add %rax, %rbx     <- address of frame 1 == return address of frame 0

			relativeRIP := frame.Lineno
			if i > 0 || frame.Type.IsInterpType(libpf.Kernel) {
				relativeRIP--
			}
			fileID, ok := pm.FileIDMapper.Get(frame.File)
			if !ok {
				log.Debugf(
					"file ID lookup failed for PID %d, frame %d/%d, frame type %d",
					trace.PID, i, traceLen, frame.Type)

				newTrace.AppendFrame(frame.Type, libpf.UnsymbolizedFileID,
					libpf.AddressOrLineno(0))
				continue
			}
			newTrace.AppendFrame(frame.Type, fileID, relativeRIP)
		default:
			err := pm.symbolizeFrame(i, trace, newTrace)
			if err != nil {
				log.Debugf(
					"symbolization failed for PID %d, frame %d/%d, frame type %d: %v",
					trace.PID, i, traceLen, frame.Type, err)

				newTrace.AppendFrame(frame.Type, libpf.UnsymbolizedFileID, libpf.AddressOrLineno(0))
			}
		}
	}
	newTrace.Hash = traceutil.HashTrace(newTrace)
	return newTrace
}

func (pm *ProcessManager) SymbolizationComplete(traceCaptureKTime times.KTime) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	nowKTime := times.GetKTime()

	for pid, pidExitKTime := range pm.exitEvents {
		if pidExitKTime > traceCaptureKTime {
			continue
		}
		for _, instance := range pm.interpreters[pid] {
			if err := instance.Detach(pm.ebpf, pid); err != nil {
				log.Errorf("Failed to handle interpreted process exit for PID %d: %v",
					pid, err)
			}
		}
		delete(pm.interpreters, pid)
		delete(pm.exitEvents, pid)

		log.Debugf("PID %v exit latency %v ms", pid, (nowKTime-pidExitKTime)/1e6)
	}
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
