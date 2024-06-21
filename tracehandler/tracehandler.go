/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package tracehandler converts raw BPF traces into the enriched user-mode
// format and then forwards them to the reporter.
package tracehandler

import (
	"context"
	"fmt"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/containermetadata"
	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/memorydebug"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/util"
)

// metadataWarnInhibDuration defines the minimum duration between warnings printed
// about failure to obtain metadata for a single PID.
const metadataWarnInhibDuration = 1 * time.Minute

// Compile time check to make sure config.Times satisfies the interfaces.
var _ Times = (*config.Times)(nil)

// Times is a subset of config.IntervalsAndTimers.
type Times interface {
	MonitorInterval() time.Duration
	BootTimeUnixNano() int64
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
	ConvertTrace(trace *host.Trace) *libpf.Trace

	// SymbolizationComplete is called after a group of Trace has been symbolized.
	// It gets the timestamp of when the Traces (if any) were captured. The timestamp
	// is in essence an indicator that all Traces until that time have been now processed,
	// and any events up to this time can be processed.
	SymbolizationComplete(traceCaptureKTime util.KTime)
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

	// containerMetadataHandler retrieves the metadata associated with the pod or container.
	containerMetadataHandler containermetadata.Handler

	// metadataWarnInhib tracks inhibitions for warnings printed about failure to
	// update container metadata (rate-limiting).
	metadataWarnInhib *lru.LRU[util.PID, libpf.Void]

	times Times
}

// newTraceHandler creates a new traceHandler
func newTraceHandler(containerMetadataHandler containermetadata.Handler,
	rep reporter.TraceReporter, traceProcessor TraceProcessor, times Times) (
	*traceHandler, error) {
	cacheSize := config.TraceCacheEntries()

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

	metadataWarnInhib, err := lru.New[util.PID, libpf.Void](64, util.PID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata warning inhibitor LRU: %v", err)
	}
	metadataWarnInhib.SetLifetime(metadataWarnInhibDuration)

	t := &traceHandler{
		traceProcessor:           traceProcessor,
		bpfTraceCache:            bpfTraceCache,
		umTraceCache:             umTraceCache,
		reporter:                 rep,
		times:                    times,
		containerMetadataHandler: containerMetadataHandler,
		metadataWarnInhib:        metadataWarnInhib,
	}

	return t, nil
}

func (m *traceHandler) HandleTrace(bpfTrace *host.Trace) {
	defer m.traceProcessor.SymbolizationComplete(bpfTrace.KTime)
	timestamp := libpf.UnixTime64(m.times.BootTimeUnixNano() + int64(bpfTrace.KTime))

	meta, err := m.containerMetadataHandler.GetContainerMetadata(bpfTrace.PID)
	if err != nil {
		log.Warnf("Failed to determine container info for trace: %v", err)
	}

	if !m.reporter.SupportsReportTraceEvent() {
		// Fast path: if the trace is already known remotely, we just send a counter update.
		postConvHash, traceKnown := m.bpfTraceCache.Get(bpfTrace.Hash)
		if traceKnown {
			m.bpfTraceCacheHit++
			svcName := m.traceProcessor.MaybeNotifyAPMAgent(bpfTrace, postConvHash, 1)
			m.reporter.ReportCountForTrace(postConvHash, timestamp, 1,
				bpfTrace.Comm, meta.PodName, meta.ContainerName, svcName)
			return
		}
		m.bpfTraceCacheMiss++
	}

	// Slow path: convert trace.
	umTrace := m.traceProcessor.ConvertTrace(bpfTrace)
	log.Debugf("Trace hash remap 0x%x -> 0x%x", bpfTrace.Hash, umTrace.Hash)
	m.bpfTraceCache.Add(bpfTrace.Hash, umTrace.Hash)

	svcName := m.traceProcessor.MaybeNotifyAPMAgent(bpfTrace, umTrace.Hash, 1)
	if m.reporter.SupportsReportTraceEvent() {
		m.reporter.ReportTraceEvent(umTrace, timestamp,
			bpfTrace.Comm, meta.PodName, meta.ContainerName, svcName)
		return
	}
	m.reporter.ReportCountForTrace(umTrace.Hash, timestamp, 1,
		bpfTrace.Comm, meta.PodName, meta.ContainerName, svcName)

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
func Start(ctx context.Context, containerMetadataHandler containermetadata.Handler,
	rep reporter.TraceReporter, traceProcessor TraceProcessor,
	traceInChan <-chan *host.Trace, times Times,
) (workerExited <-chan libpf.Void, err error) {
	handler, err := newTraceHandler(containerMetadataHandler, rep, traceProcessor, times)
	if err != nil {
		return nil, fmt.Errorf("failed to create traceHandler: %v", err)
	}

	exitChan := make(chan libpf.Void)

	go func() {
		defer close(exitChan)

		metricsTicker := time.NewTicker(times.MonitorInterval())
		defer metricsTicker.Stop()

		// Poll the output channels
		for {
			select {
			case traceUpdate := <-traceInChan:
				handler.HandleTrace(traceUpdate)
			case <-metricsTicker.C:
				handler.collectMetrics()
			case <-ctx.Done():
				return
			}
			// Output memory usage in debug builds.
			memorydebug.DebugLogMemoryUsage()
		}
	}()

	return exitChan, nil
}
