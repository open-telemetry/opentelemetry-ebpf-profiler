// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package tracehandler converts raw BPF traces into the enriched user-mode
// format and then forwards them to the reporter.
package tracehandler // import "go.opentelemetry.io/ebpf-profiler/tracehandler"

import (
	"context"
	"fmt"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// metadataWarnInhibDuration defines the minimum duration between warnings printed
// about failure to obtain metadata for a single PID.
const metadataWarnInhibDuration = 1 * time.Minute

// Compile time check to make sure config.Times satisfies the interfaces.
var _ Times = (*times.Times)(nil)

// Times is a subset of config.IntervalsAndTimers.
type Times interface {
	MonitorInterval() time.Duration
}

// TraceProcessor is an interface used by traceHandler to convert traces
// from a form received from eBPF to the form we wish to dispatch to the
// collection agent.
type TraceProcessor interface {
	// MaybeNotifyAPMAgent notifies a potentially existing connected APM agent
	// that a stack trace was collected in their process. If an APM agent is
	// listening, the service name is returned.
	MaybeNotifyAPMAgent(rawTrace *host.Trace, umTraceHash libpf.TraceHash, count uint16) string

	// ConvertTrace converts a trace from eBPF into the form we want to send to
	// the collection agent. Depending on the frame type it will attempt to symbolize
	// the frame and send the associated metadata to the collection agent.
	ConvertTrace(trace *host.Trace) (*libpf.Trace, error)

	// ProcessedUntil is called periodically after Traces are processed/symbolized.
	// It gets the timestamp of when the Traces (if any) were captured. The timestamp
	// is in essence an indicator that all Traces until that time have been now processed,
	// and any events and cleanup actions up to this time can be processed.
	ProcessedUntil(traceCaptureKTime times.KTime)
}

// traceHandler provides functions for handling new traces and trace count updates
// from the eBPF components.
type traceHandler struct {
	// Metrics
	umTraceCacheHit   uint64
	umTraceCacheMiss  uint64
	bpfTraceCacheHit  uint64
	bpfTraceCacheMiss uint64

	traceProcessor TraceProcessor

	// bpfTraceCache stores mappings from BPF to user-mode hashes. This allows
	// avoiding the overhead of re-doing user-mode symbolization of traces that
	// we have recently seen already.
	bpfTraceCache *lru.LRU[host.TraceHash, libpf.TraceHash]

	// umTraceCache is a LRU set that suppresses unnecessary resends of traces
	// that we have recently reported to the collector already.
	umTraceCache *lru.LRU[libpf.TraceHash, libpf.Void]

	// reporter instance to use to send out traces.
	reporter reporter.TraceReporter

	// metadataWarnInhib tracks inhibitions for warnings printed about failure to
	// update container metadata (rate-limiting).
	metadataWarnInhib *lru.LRU[libpf.PID, libpf.Void]

	times Times
}

// newTraceHandler creates a new traceHandler
func newTraceHandler(rep reporter.TraceReporter, traceProcessor TraceProcessor,
	intervals Times, cacheSize uint32) (*traceHandler, error) {
	bpfTraceCache, err := lru.New[host.TraceHash, libpf.TraceHash](
		cacheSize, func(k host.TraceHash) uint32 { return uint32(k) })
	if err != nil {
		return nil, err
	}

	umTraceCache, err := lru.New[libpf.TraceHash, libpf.Void](
		cacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	metadataWarnInhib, err := lru.New[libpf.PID, libpf.Void](64, libpf.PID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata warning inhibitor LRU: %v", err)
	}
	metadataWarnInhib.SetLifetime(metadataWarnInhibDuration)

	t := &traceHandler{
		traceProcessor:    traceProcessor,
		bpfTraceCache:     bpfTraceCache,
		umTraceCache:      umTraceCache,
		reporter:          rep,
		times:             intervals,
		metadataWarnInhib: metadataWarnInhib,
	}

	return t, nil
}

func (m *traceHandler) HandleTrace(bpfTrace *host.Trace) {
	meta := &samples.TraceEventMeta{
		Timestamp:      libpf.UnixTime64(bpfTrace.KTime.UnixNano()),
		Comm:           bpfTrace.Comm,
		PID:            bpfTrace.PID,
		TID:            bpfTrace.TID,
		APMServiceName: "", // filled in below
		CPU:            bpfTrace.CPU,
		ProcessName:    bpfTrace.ProcessName,
		ExecutablePath: bpfTrace.ExecutablePath,
		Origin:         bpfTrace.Origin,
		OffTime:        bpfTrace.OffTime,
	}

	if !m.reporter.SupportsReportTraceEvent() {
		// Fast path: if the trace is already known remotely, we just send a counter update.
		postConvHash, traceKnown := m.bpfTraceCache.Get(bpfTrace.Hash)
		if traceKnown {
			m.bpfTraceCacheHit++
			meta.APMServiceName = m.traceProcessor.MaybeNotifyAPMAgent(bpfTrace, postConvHash, 1)
			m.reporter.ReportCountForTrace(postConvHash, 1, meta)
			return
		}
		m.bpfTraceCacheMiss++
	}

	// Slow path: convert trace.
	umTrace, err := m.traceProcessor.ConvertTrace(bpfTrace)
	if err != nil {
		// Never happens except for coredump testing.
		panic(err)
	}
	log.Debugf("Trace hash remap 0x%x -> 0x%x", bpfTrace.Hash, umTrace.Hash)
	m.bpfTraceCache.Add(bpfTrace.Hash, umTrace.Hash)

	meta.APMServiceName = m.traceProcessor.MaybeNotifyAPMAgent(bpfTrace, umTrace.Hash, 1)
	if m.reporter.SupportsReportTraceEvent() {
		m.reporter.ReportTraceEvent(umTrace, meta)
		return
	}
	m.reporter.ReportCountForTrace(umTrace.Hash, 1, meta)

	// Trace already known to collector by UM hash?
	if _, known := m.umTraceCache.Get(umTrace.Hash); known {
		m.umTraceCacheHit++
		return
	}
	m.umTraceCacheMiss++

	// Nope. Send it now.
	m.reporter.ReportFramesForTrace(umTrace)
	m.umTraceCache.Add(umTrace.Hash, libpf.Void{})
}

// Start starts a goroutine that receives and processes trace updates over
// the given channel. Updates are sent periodically to the collection agent.
// The returned channel allows the caller to wait for the background worker
// to exit after a cancellation through the context.
func Start(ctx context.Context, rep reporter.TraceReporter, traceProcessor TraceProcessor,
	traceInChan <-chan *host.Trace, intervals Times, cacheSize uint32,
) (workerExited <-chan libpf.Void, err error) {
	handler, err :=
		newTraceHandler(rep, traceProcessor, intervals, cacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create traceHandler: %v", err)
	}

	exitChan := make(chan libpf.Void)

	go func() {
		defer close(exitChan)

		metricsTicker := time.NewTicker(intervals.MonitorInterval())
		defer metricsTicker.Stop()

		// Poll the output channels
		for {
			select {
			case traceUpdate := <-traceInChan:
				if traceUpdate != nil {
					handler.HandleTrace(traceUpdate)
				}
			case <-metricsTicker.C:
				handler.collectMetrics()
			case <-ctx.Done():
				return
			}
		}
	}()

	return exitChan, nil
}
