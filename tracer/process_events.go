// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"context"
	"fmt"

	"github.com/elastic/go-perf"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// ensureMmapEventMonitor starts system-wide perf readers once. Executable mapping
// events enter the existing PID path so probes see mappings added after initial sync.
func (t *Tracer) ensureMmapEventMonitor() error {
	return t.mmapEventOnce()
}

func (t *Tracer) startMmapEventMonitor(ctx context.Context) error {
	t.mmapEventMu.Lock()
	defer t.mmapEventMu.Unlock()

	// Close cancels the lifecycle context before acquiring mmapEventMu. If it
	// won the race with startup, do not create resources after shutdown.
	if err := ctx.Err(); err != nil {
		return err
	}

	cpus, err := onlineCPUsOnce()
	if err != nil {
		return fmt.Errorf("getting online CPUs: %w", err)
	}

	attr := &perf.Attr{
		Options: perf.Options{
			Disabled:  true, // Enable only after every per-CPU ring has been mapped.
			Mmap2:     true, // Emit extended records for executable mappings.
			Watermark: true, // Wake readers based on unread bytes, not sample count.
		},
	}
	// The dummy event only carries executable mapping sideband records.
	attr.SetSamplePeriod(1)
	// Wake readers when any data reaches the ring; sample-count wakeups ignore sideband records.
	attr.SetWakeupWatermark(1)
	if err := perf.Dummy.Configure(attr); err != nil {
		return fmt.Errorf("configuring mmap events: %w", err)
	}

	events := make([]*perf.Event, 0, len(cpus))
	closeEvents := func() {
		for _, event := range events {
			_ = event.Close()
		}
	}

	// System-wide perf events require a concrete CPU, so open one per online CPU.
	for _, cpu := range cpus {
		event, err := perf.Open(attr, perf.AllThreads, cpu, nil)
		if err != nil {
			closeEvents()
			return fmt.Errorf("opening mmap events on CPU %d: %w", cpu, err)
		}
		events = append(events, event)
		if err := event.MapRing(); err != nil {
			closeEvents()
			return fmt.Errorf("mapping mmap event ring on CPU %d: %w", cpu, err)
		}
	}

	for _, event := range events {
		if err := event.Enable(); err != nil {
			closeEvents()
			return fmt.Errorf("enabling mmap events: %w", err)
		}
	}
	for _, event := range events {
		t.mmapEventWG.Go(func() {
			t.readMmapEvents(ctx, event)
		})
	}
	return nil
}

// readMmapEvents forwards one CPU's mapping events to PID processing.
func (t *Tracer) readMmapEvents(ctx context.Context, event *perf.Event) {
	defer event.Close()
	for {
		record, err := event.ReadRecord(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Errorf("Failed to read perf mmap event: %v", err)
			}
			return
		}
		if lost, ok := record.(*perf.LostRecord); ok {
			log.Warnf("Lost %d perf mmap events", lost.Lost)
			continue
		}
		pidTID, ok := mmapRecordPIDTID(record)
		if !ok {
			continue
		}
		select {
		case t.pidEvents <- pidTID:
		case <-ctx.Done():
			return
		}
	}
}

func mmapRecordPIDTID(record perf.Record) (libpf.PIDTID, bool) {
	var pid, tid uint32
	switch record := record.(type) {
	case *perf.Mmap2Record:
		// Mappings without a backing inode, such as anonymous JIT code, cannot
		// provide a file-backed ELF probe target and would only trigger an
		// unnecessary full process resync.
		if record.Inode == 0 {
			return 0, false
		}
		pid, tid = record.Pid, record.Tid
	default:
		return 0, false
	}
	return libpf.PIDTID(uint64(pid)<<32 | uint64(tid)), true
}
