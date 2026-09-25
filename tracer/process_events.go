// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"context"
	"debug/elf"
	"fmt"

	"github.com/elastic/go-perf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/internal/perfutil"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// mmapEventRingPages sizes the per-CPU perf ring buffer used for mmap events.
// mmap2 records are small, so the default (128 pages) is far larger than needed;
// a smaller ring keeps the system-wide, per-CPU memory footprint modest.
const mmapEventRingPages = 8

// mmapEventBufferSize sizes the channel that carries mmap mapping events to the
// PID event processor. It is separate from pidEvents so a burst of mmap records
// cannot starve eBPF report_pid notifications.
const mmapEventBufferSize = 128

// mmapEvent is a single executable, file-backed mapping observed via a perf
// mmap2 record, routed to ProcessManager.SynchronizeMapping.
type mmapEvent struct {
	pid     libpf.PID
	tid     libpf.PID
	mapping process.RawMapping
}

// ensureMmapEventMonitor starts system-wide perf readers once. Executable mapping
// events are ingested via ProcessManager.SynchronizeMapping so probes see
// mappings added after the initial process synchronization.
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
	ev, ok := mmapRecordToEvent(record)
	if !ok {
		return
	}
	select {
	case t.mmapEvents <- ev:
	case <-ctx.Done():
	}
}

// mmapRecordToEvent converts a perf mmap2 record into an mmapEvent, dropping
// records that cannot describe a file-backed ELF probe target.
func mmapRecordToEvent(record perf.Record) (mmapEvent, bool) {
	rec, ok := record.(*perf.Mmap2Record)
	if !ok {
		return mmapEvent{}, false
	}
	// Mappings without a backing inode, such as anonymous JIT code, cannot
	// provide a file-backed ELF probe target.
	if rec.Inode == 0 {
		return mmapEvent{}, false
	}
	return mmapEvent{
		pid: libpf.PID(rec.Pid),
		tid: libpf.PID(rec.Tid),
		mapping: process.RawMapping{
			Vaddr:      rec.Addr,
			Length:     rec.Len,
			Flags:      protToProgFlags(rec.Prot),
			FileOffset: rec.PageOffset,
			// Encode the device like /proc/PID/maps parsing (stat(2) st_dev).
			Device: unix.Mkdev(rec.MajorID, rec.MinorID),
			Inode:  rec.Inode,
			Path:   rec.Filename,
		},
	}, true
}

// protToProgFlags maps mmap PROT_* protection bits to ELF program flags, as used
// by process.RawMapping.
func protToProgFlags(prot uint32) elf.ProgFlag {
	var flags elf.ProgFlag
	if prot&unix.PROT_READ != 0 {
		flags |= elf.PF_R
	}
	if prot&unix.PROT_WRITE != 0 {
		flags |= elf.PF_W
	}
	if prot&unix.PROT_EXEC != 0 {
		flags |= elf.PF_X
	}
	return flags
}
