// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"context"
	"fmt"

	"github.com/elastic/go-perf"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/internal/perfutil"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// mmapEventRingPages sizes the per-CPU perf ring buffer used for mmap events.
// mmap2 records are small, so the default (128 pages) is far larger than needed;
// a smaller ring keeps the system-wide, per-CPU memory footprint modest.
const mmapEventRingPages = 8

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

	reader, err := perfutil.Start(ctx, cpus, perfutil.Config{
		Name:      "mmap event",
		RingPages: mmapEventRingPages,
		Configure: func(attr *perf.Attr) {
			// Mmap2 emits extended mapping records, but the kernel only
			// delivers them when Mmap is also set (see perf_event_open(2)).
			attr.Options.Mmap = true
			attr.Options.Mmap2 = true
		},
		OnRecord: t.handleMmapRecord,
	})
	if err != nil {
		return err
	}
	t.mmapReader = reader
	return nil
}

// handleMmapRecord forwards one mapping event to PID processing.
func (t *Tracer) handleMmapRecord(ctx context.Context, record perf.Record) {
	if lost, ok := record.(*perf.LostRecord); ok {
		log.Warnf("Lost %d perf mmap events", lost.Lost)
		return
	}
	pidTID, ok := mmapRecordPIDTID(record)
	if !ok {
		return
	}
	select {
	case t.pidEvents <- pidTID:
	case <-ctx.Done():
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
