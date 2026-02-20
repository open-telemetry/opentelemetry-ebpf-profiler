// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package tracehandler converts raw BPF traces into the enriched user-mode
// format and then forwards them to the reporter.
package tracehandler // import "go.opentelemetry.io/ebpf-profiler/tracehandler"

import (
	"context"
	"fmt"
	"sync"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/times"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// Compile time check to make sure config.Times satisfies the interfaces.
var _ Times = (*times.Times)(nil)

// Times is a subset of config.IntervalsAndTimers.
type Times interface {
	MonitorInterval() time.Duration
}

// Default lifetime of elements in the cache to reduce recurring
// symbolization efforts.
var traceCacheLifetime = 5 * time.Minute

// TraceInterceptor is called after ConvertTrace with the symbolized trace,
// metadata, and original BPF trace. Return true to consume the trace
// (skip caching and reporting), false to proceed normally.
type TraceInterceptor func(trace *libpf.Trace, meta *samples.TraceEventMeta,
	rawTrace *host.Trace) bool

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
	traceCacheHit  uint64
	traceCacheMiss uint64

	traceProcessor TraceProcessor

	// traceCache stores mappings from BPF hashes to symbolized traces. This allows
	// avoiding the overhead of re-doing user-mode symbolization of traces that
	// we have recently seen already.
	traceCache *lru.SyncedLRU[host.TraceHash, libpf.Trace]

	// reporter instance to use to send out traces.
	reporter reporter.TraceReporter

	// interceptor, if set, is called after ConvertTrace on cache-miss.
	// If it returns true the trace is consumed and not cached or reported.
	interceptor TraceInterceptor

	times Times
}

// newTraceHandler creates a new traceHandler
func newTraceHandler(ctx context.Context, rep reporter.TraceReporter,
	traceProcessor TraceProcessor, intervals Times, cacheSize uint32,
	interceptor TraceInterceptor) (*traceHandler, error) {
	traceCache, err := lru.NewSynced[host.TraceHash, libpf.Trace](
		cacheSize, func(k host.TraceHash) uint32 { return uint32(k) })
	if err != nil {
		return nil, err
	}
	// Do not hold elements indefinitely in the cache.
	traceCache.SetLifetime(traceCacheLifetime)

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		wg.Done()
		ticker := time.NewTicker(traceCacheLifetime)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				traceCache.PurgeExpired()
			}
		}
	}()

	// Wait to make sure the purge routine did start.
	wg.Wait()

	return &traceHandler{
		traceProcessor: traceProcessor,
		traceCache:     traceCache,
		reporter:       rep,
		interceptor:    interceptor,
		times:          intervals,
	}, nil
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
		ContainerID:    bpfTrace.ContainerID,
		Origin:         bpfTrace.Origin,
		OffTime:        bpfTrace.OffTime,
		EnvVars:        bpfTrace.EnvVars,
	}

	if trace, exists := m.traceCache.GetAndRefresh(bpfTrace.Hash,
		traceCacheLifetime); exists {
		m.traceCacheHit++
		// Fast path
		meta.APMServiceName = m.traceProcessor.MaybeNotifyAPMAgent(bpfTrace, trace.Hash, 1)
		if err := m.reporter.ReportTraceEvent(&trace, meta); err != nil {
			log.Errorf("Failed to report trace event: %v", err)
		}
		return
	}
	m.traceCacheMiss++

	// Slow path: convert trace.
	umTrace, err := m.traceProcessor.ConvertTrace(bpfTrace)
	if err != nil {
		// Never happens except for coredump testing.
		panic(err)
	}
	log.Debugf("Trace hash remap 0x%x -> 0x%x", bpfTrace.Hash, umTrace.Hash)

	// If an interceptor is set and consumes the trace, skip caching and reporting.
	// CUDA traces are always intercepted here and never cached.
	if m.interceptor != nil && m.interceptor(umTrace, meta, bpfTrace) {
		return
	}

	m.traceCache.Add(bpfTrace.Hash, *umTrace)

	meta.APMServiceName = m.traceProcessor.MaybeNotifyAPMAgent(bpfTrace, umTrace.Hash, 1)
	if err := m.reporter.ReportTraceEvent(umTrace, meta); err != nil {
		log.Errorf("Failed to report trace event: %v", err)
	}
}

// Start starts a goroutine that receives and processes trace updates over
// the given channel. Updates are sent periodically to the collection agent.
// The returned channel allows the caller to wait for the background worker
// to exit after a cancellation through the context.
func Start(ctx context.Context, rep reporter.TraceReporter, traceProcessor TraceProcessor,
	traceInChan <-chan *host.Trace, intervals Times, cacheSize uint32,
	interceptor TraceInterceptor,
) (workerExited <-chan libpf.Void, err error) {
	handler, err :=
		newTraceHandler(ctx, rep, traceProcessor, intervals, cacheSize, interceptor)
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
