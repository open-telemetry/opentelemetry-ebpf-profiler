//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package perfutil provides helpers for consuming PERF_COUNT_SW_DUMMY sideband
// records (such as mmap2 or ksymbol events) across all online CPUs.
package perfutil // import "go.opentelemetry.io/ebpf-profiler/internal/perfutil"

import (
	"context"
	"fmt"
	"sync"

	"github.com/elastic/go-perf"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// Config configures a PerfSidebandReader.
type Config struct {
	// Name identifies the reader in log and error messages.
	Name string

	// RingPages sizes each per-CPU ring buffer, in pages. Zero uses
	// perf.DefaultNumPages. Sideband records are small, so callers can usually
	// pick a much smaller ring than the default.
	RingPages int

	// Configure customizes the shared perf.Attr before the events are opened.
	// The attr is already set up as a disabled PERF_COUNT_SW_DUMMY event with
	// watermark-based wakeups; callers typically only enable the sideband
	// records they care about (e.g. attr.Options.Mmap2 or attr.Options.KSymbol).
	Configure func(attr *perf.Attr)

	// OnRecord handles each record read from any CPU's ring buffer. It must not
	// block indefinitely: use ctx to abort channel sends during shutdown.
	OnRecord func(ctx context.Context, record perf.Record)
}

// PerfSidebandReader owns one PERF_COUNT_SW_DUMMY perf event per CPU and forwards
// the sideband records they emit to a handler until its context is canceled.
type PerfSidebandReader struct {
	name   string
	events []*perf.Event
	wg     sync.WaitGroup
}

// Start opens a dummy perf event on every CPU in cpus, maps a ring buffer,
// enables the events, and spawns one goroutine per CPU that forwards records to
// cfg.OnRecord until ctx is canceled. On error, any events already opened are
// closed before returning.
func Start(ctx context.Context, cpus []int, cfg Config) (*PerfSidebandReader, error) {
	attr := new(perf.Attr)
	perf.Dummy.Configure(attr)
	// Keep the events disabled until every ring is mapped, so no records are
	// delivered before their reader can drain them.
	attr.Options.Disabled = true
	// Wake readers as soon as any data reaches the ring; sample-count wakeups
	// ignore sideband records. SetWakeupWatermark also sets Options.Watermark.
	attr.SetWakeupWatermark(1)
	if cfg.Configure != nil {
		cfg.Configure(attr)
	}

	ringPages := cfg.RingPages
	if ringPages == 0 {
		ringPages = perf.DefaultNumPages
	}

	r := &PerfSidebandReader{name: cfg.Name}

	// System-wide perf events require a concrete CPU, so open one per online CPU.
	for _, cpu := range cpus {
		event, err := perf.Open(attr, perf.AllThreads, cpu, nil)
		if err != nil {
			r.closeEvents()
			return nil, fmt.Errorf("opening %s perf event on CPU %d: %w", cfg.Name, cpu, err)
		}
		r.events = append(r.events, event)
		if err := event.MapRingNumPages(ringPages); err != nil {
			r.closeEvents()
			return nil, fmt.Errorf("mapping %s ring on CPU %d: %w", cfg.Name, cpu, err)
		}
	}

	// Enable only after every ring has been mapped.
	for _, event := range r.events {
		if err := event.Enable(); err != nil {
			r.closeEvents()
			return nil, fmt.Errorf("enabling %s perf event: %w", cfg.Name, err)
		}
	}

	for _, event := range r.events {
		r.wg.Go(func() {
			r.read(ctx, event, cfg.OnRecord)
		})
	}
	return r, nil
}

// read forwards one CPU's records to onRecord until ctx is canceled or a read
// fails.
func (r *PerfSidebandReader) read(ctx context.Context, event *perf.Event,
	onRecord func(context.Context, perf.Record)) {
	for {
		record, err := event.ReadRecord(ctx)
		if err != nil {
			if ctx.Err() == nil {
				log.Errorf("Failed to read %s perf event: %v", r.name, err)
			}
			return
		}
		onRecord(ctx, record)
	}
}

// Close waits for the reader goroutines to exit, then disables and closes every
// perf event. Cancel the context passed to Start before calling Close so the
// readers stop before the events are torn down; otherwise go-perf may send on a
// closed channel and panic.
func (r *PerfSidebandReader) Close() {
	r.wg.Wait()
	r.closeEvents()
}

func (r *PerfSidebandReader) closeEvents() {
	for _, event := range r.events {
		if err := event.Disable(); err != nil {
			log.Errorf("Failed to disable %s perf event: %v", r.name, err)
		}
		if err := event.Close(); err != nil {
			log.Errorf("Failed to close %s perf event: %v", r.name, err)
		}
	}
	r.events = nil
}
