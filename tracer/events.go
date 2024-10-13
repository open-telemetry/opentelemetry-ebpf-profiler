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
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/support"
)

/*
#include <stdint.h>
#include "../support/ebpf/types.h"
*/
import "C"

const (
	// Length of the pidEvents channel. It must be large enough so the
	// consuming goroutine doesn't go idle due to scheduling, but small enough
	// so that the hostagent startup phase can wait on most PID notifications
	// to be processed before starting the tracer.
	pidEventBufferSize = 10
)

// StartPIDEventProcessor spawns a goroutine to process PID events.
func (t *Tracer) StartPIDEventProcessor(ctx context.Context) error {
	go t.processPIDEvents(ctx)
	return t.populatePIDs(ctx)
}

// Process the PID events that are incoming in the Tracer channel.
func (t *Tracer) processPIDEvents(ctx context.Context) {
	pidCleanupTicker := time.NewTicker(t.intervals.PIDCleanupInterval())
	defer pidCleanupTicker.Stop()
	for {
		select {
		case pid := <-t.pidEvents:
			t.processManager.SynchronizeProcess(process.New(pid))
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

// triggerPidEvent is a trigger function for the eBPF map report_events. It is
// called for every event that is received in user space from this map. The underlying
// C structure in the received data is transformed to a Go structure and the event
// handler is invoked.
func (t *Tracer) triggerPidEvent(data []byte) {
	fmt.Println("Trigger PID event")
	event := (*C.Event)(unsafe.Pointer(&data[0]))
	if event.event_type == support.EventTypeGenericPID {
		t.handleGenericPID()
	}
}

// startPerfEventMonitor spawns a goroutine that receives events from the given
// perf event map by waiting for events the kernel. Every event in the buffer
// will wake up user-land.
//
// For each received event, triggerFunc is called. triggerFunc may NOT store
// references into the buffer that it is given: the buffer is re-used across
// calls. Returns a function that can be called to retrieve perf event array
// error counts.
func startPerfEventMonitor(ctx context.Context, perfEventMap *ebpf.Map,
	triggerFunc func([]byte), perCPUBufferSize int) func() (lost, noData, readError uint64) {
	eventReader, err := perf.NewReader(perfEventMap, perCPUBufferSize)
	if err != nil {
		log.Fatalf("Failed to setup perf reporting via %s: %v", perfEventMap, err)
	}
	fmt.Println("Start perf event monitor")
	var lostEventsCount, readErrorCount, noDataCount atomic.Uint64
	go func() {
		var data perf.Record
		for {
			select {
			case <-ctx.Done():
				return
			default:
				if err := eventReader.ReadInto(&data); err != nil {
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
		}
	}()

	return func() (lost, noData, readError uint64) {
		lost = lostEventsCount.Swap(0)
		noData = noDataCount.Swap(0)
		readError = readErrorCount.Swap(0)
		return
	}
}

// startPollingPerfEventMonitor spawns a goroutine that receives events from
// the given perf event map by periodically polling the perf event buffer.
// Events written to the perf event buffer do not wake user-land immediately.
//
// For each received event, triggerFunc is called. triggerFunc may NOT store
// references into the buffer that it is given: the buffer is re-used across
// calls. Returns a function that can be called to retrieve perf event array
// error counts.
func startPollingPerfEventMonitor(ctx context.Context, perfEventMap *ebpf.Map,
	pollFrequency time.Duration, perCPUBufferSize int, triggerFunc func([]byte),
) func() (lost, noData, readError uint64) {
	eventReader, err := perf.NewReader(perfEventMap, perCPUBufferSize)
	if err != nil {
		log.Fatalf("Failed to setup perf reporting via %s: %v", perfEventMap, err)
	}

	// A deadline of zero is treated as "no deadline". A deadline in the past
	// means "always return immediately". We thus set a deadline 1 second after
	// unix epoch to always ensure the latter behavior.
	eventReader.SetDeadline(time.Unix(1, 0))

	pollTicker := time.NewTicker(pollFrequency)

	var lostEventsCount, readErrorCount, noDataCount atomic.Uint64
	go func() {
		var data perf.Record

	PollLoop:
		for {
			select {
			case <-pollTicker.C:
				// Continue execution below.
			case <-ctx.Done():
				break PollLoop
			}

			// Eagerly read events until the buffer is exhausted.
			for {
				if err = eventReader.ReadInto(&data); err != nil {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						readErrorCount.Add(1)
					}

					break
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
		}
	}()

	return func() (lost, noData, readError uint64) {
		lost = lostEventsCount.Swap(0)
		noData = noDataCount.Swap(0)
		readError = readErrorCount.Swap(0)
		return
	}
}

// startEventMonitor spawns a goroutine that receives events from the
// map report_events. Returns a function that can be called to retrieve
// perf event array metrics.
func (t *Tracer) startEventMonitor(ctx context.Context) func() []metrics.Metric {
	eventMap, ok := t.ebpfMaps["report_events"]
	if !ok {
		log.Fatalf("Map report_events is not available")
	}
	fmt.Println("Start event monitor")
	fmt.Println("Event map: ", eventMap)
	getPerfErrorCounts := startPerfEventMonitor(ctx, eventMap, t.triggerPidEvent, os.Getpagesize())
	return func() []metrics.Metric {
		lost, noData, readError := getPerfErrorCounts()

		return []metrics.Metric{
			{ID: metrics.IDPerfEventLost, Value: metrics.MetricValue(lost)},
			{ID: metrics.IDPerfEventNoData, Value: metrics.MetricValue(noData)},
			{ID: metrics.IDPerfEventReadError, Value: metrics.MetricValue(readError)},
		}
	}
}
