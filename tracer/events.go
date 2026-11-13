// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	// Length of the pidEvents channel. It must be large enough so the
	// consuming goroutine doesn't go idle due to scheduling, but small enough
	// so that the hostagent startup phase can wait on most PID notifications
	// to be processed before starting the tracer.
	pidEventBufferSize = 10
	// Maximum number of trace events to process in one batch. This is used as a
	// safe threshold for when off-cpu profiling is enabled, as the kernel can generate
	// enough events to completely monopolize userspace processing. If more than maxEvents
	// events are produced by the kernel between two polling intervals, the queue from bpf
	// to userspace will fill up and the kernel will start dropping events.
	maxEvents = 4096
)

// StartPIDEventProcessor spawns a goroutine to process PID events.
func (t *Tracer) StartPIDEventProcessor(ctx context.Context) {
	go t.processPIDEvents(ctx)
}

// Process the PID events that are incoming in the Tracer channel.
func (t *Tracer) processPIDEvents(ctx context.Context) {
	pidCleanupTicker := time.NewTicker(t.intervals.PIDCleanupInterval())
	defer pidCleanupTicker.Stop()
	for {
		select {
		case pidTid := <-t.pidEvents:
			t.processManager.SynchronizeProcess(process.New(pidTid.PID(), pidTid.TID()))
		case <-pidCleanupTicker.C:
			t.processManager.CleanupPIDs()
		case <-ctx.Done():
			return
		}
	}
}

// handleGenericPID triggers immediate processing of eBPF-reported PIDs.
// WARNING: Not executed as a goroutine: needs to stay lightweight, and nonblocking.
func (t *Tracer) handleGenericPID() {
	// Non-blocking trigger sending. If the attempt would block
	// some other goroutine is already sending this notification.
	select {
	case t.triggerPIDProcessing <- true:
	default:
	}
}

// triggerReportEvent is a trigger function for the eBPF map report_events. It is
// called for every event that is received in user space from this map. The underlying
// C structure in the received data is transformed to a Go structure and the event
// handler is invoked.
func (t *Tracer) triggerReportEvent(data []byte) {
	event := (*support.Event)(unsafe.Pointer(&data[0]))
	switch event.Type {
	case support.EventTypeGenericPID:
		t.handleGenericPID()
	}
}

// startPerfEventMonitor spawns a goroutine that receives events from the given
// perf event map by waiting for events from the kernel. Every event in the buffer
// will wake up userspace.
//
// For each received event, triggerFunc is called. triggerFunc may NOT store
// references into the buffer that it is given: the buffer is reused across
// calls. Returns a function that can be called to retrieve perf event array
// error counts.
func startPerfEventMonitor(ctx context.Context, perfEventMap *ebpf.Map,
	triggerFunc func([]byte), perCPUBufferSize int,
) (func() (lost, noData, readError uint64), error) {
	eventReader, err := perf.NewReader(perfEventMap, perCPUBufferSize)
	if err != nil {
		return nil, fmt.Errorf("failed to setup perf reporting via %s: %v", perfEventMap, err)
	}

	var lostEventsCount, readErrorCount, noDataCount atomic.Uint64
	go func() {
		defer eventReader.Close()
		context.AfterFunc(ctx, func() { _ = eventReader.Close() })

		var data perf.Record
		for {

			if err := eventReader.ReadInto(&data); err != nil {
				if errors.Is(err, os.ErrClosed) {
					return
				}
				readErrorCount.Add(1)
				continue
			}
			if data.LostSamples != 0 {
				lostEventsCount.Add(data.LostSamples)
				continue
			}
			if len(data.RawSample) == 0 {
				noDataCount.Add(1)
				continue
			}
			triggerFunc(data.RawSample)
		}
	}()

	return func() (lost, noData, readError uint64) {
		lost = lostEventsCount.Swap(0)
		noData = noDataCount.Swap(0)
		readError = readErrorCount.Swap(0)
		return
	}, nil
}

// startTraceEventMonitor spawns a goroutine that receives trace events from
// the kernel by periodically polling the underlying ringbuffer.
// Events written to the ringbuffer do not wake userspace immediately.
//
// Every received record is handed to the process manager; after each batch,
// a boundary advances the exit cleanup watermark.
//
// Returns a function that can be called to retrieve ringbuffer error counts.
func (t *Tracer) startTraceEventMonitor(ctx context.Context) (func() []metrics.Metric, error) {
	eventsMap := t.ebpfMaps["trace_events"]
	eventReader, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		return nil, fmt.Errorf("failed to setup ringbuf reporting via %s: %v", eventsMap, err)
	}

	// A deadline of zero is treated as "no deadline". A deadline in the past
	// means "always return immediately". We thus set a deadline 1 second after
	// unix epoch to always ensure the latter behavior.
	// TODO: adapt this to better reflect ringbuffer behavior
	eventReader.SetDeadline(time.Unix(1, 0))

	var readErrorCount, noDataCount atomic.Uint64
	go func() {
		defer eventReader.Close()
		var data ringbuf.Record
		var eventCount int

		pollTicker := time.NewTicker(t.intervals.TracePollInterval())
		defer pollTicker.Stop()
	PollLoop:
		for {
			// We use two selects to avoid starvation in scenarios where the kernel
			// is generating a lot of events.
			select {
			// Always check for context cancellation in each iteration
			case <-ctx.Done():
				break PollLoop
			default:
				// Continue below
			}

			select {
			// This context cancellation check may not execute in timely manner
			case <-ctx.Done():
				break PollLoop
			case <-pollTicker.C:
				// Continue execution below
			}

			eventCount = 0

			// Eagerly read events until the buffer is exhausted or we reach maxEvents
			for {
				if err = eventReader.ReadInto(&data); err != nil {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						readErrorCount.Add(1)
					}
					break
				}

				// There's a theoretical possibility that this inner loop never exits if the
				// following two error cases are continuously being hit. In practice this would
				// mean that userspace doesn't manage to make ANY progress when reading events
				// (eventCount never reaching maxEvents and underlying buffers never being empty),
				// something that should not happen even with off-cpu at maximum sampling rates:
				// probabilistically, there should always be some events read per X iterations.
				// We could add a secondary fallback (ideally deterministic, e.g. maximum time
				// elapsed) to guard against that possibility if we see it as a concern (currently
				// not done).
				//
				// Regardless, the current data transmission architecture from kernel to user and
				// the -serial- event processing pipeline in the rest of the agent is not designed
				// for the data volumes that off-cpu profiling can generate and should be revisited.

				if len(data.RawSample) == 0 {
					noDataCount.Add(1)
					continue
				}

				eventCount++

				if err := t.processManager.HandleTrace(data.RawSample); err != nil {
					// A malformed record breaks the trace layout
					// contract; stop processing.
					log.Errorf("Stop receiving traces: %v", err)
					t.signalDone()
					return
				}

				if eventCount == maxEvents {
					// Bound the work done per poll tick.
					break
				}
			}
			// A batch was submitted; let the process manager advance the
			// exit cleanup watermark.
			t.processManager.BatchSubmitted()
		}
	}()

	return func() []metrics.Metric {
		noData := noDataCount.Swap(0)
		readError := readErrorCount.Swap(0)
		return []metrics.Metric{
			{ID: metrics.IDTraceEventNoData, Value: metrics.MetricValue(noData)},
			{ID: metrics.IDTraceEventReadError, Value: metrics.MetricValue(readError)},
		}
	}, nil
}

// startEventMonitor spawns a goroutine that receives events from the
// map report_events. Returns a function that can be called to retrieve
// perf event array metrics.
func (t *Tracer) startEventMonitor(ctx context.Context) (func() []metrics.Metric, error) {
	eventMap, ok := t.ebpfMaps["report_events"]
	if !ok {
		return nil, fmt.Errorf("map report_events is not available")
	}

	getPerfErrorCounts, err := startPerfEventMonitor(ctx, eventMap, t.triggerReportEvent, os.Getpagesize())
	if err != nil {
		return nil, err
	}
	return func() []metrics.Metric {
		lost, noData, readError := getPerfErrorCounts()

		return []metrics.Metric{
			{ID: metrics.IDPerfEventLost, Value: metrics.MetricValue(lost)},
			{ID: metrics.IDPerfEventNoData, Value: metrics.MetricValue(noData)},
			{ID: metrics.IDPerfEventReadError, Value: metrics.MetricValue(readError)},
		}
	}, nil
}
