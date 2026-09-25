//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms // import "go.opentelemetry.io/ebpf-profiler/kallsyms"

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/elastic/go-perf"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/internal/perfutil"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// bpfProgPrefix is the prefix the kernel uses for all JIT'd BPF program
// symbols in /proc/kallsyms and PERF_RECORD_KSYMBOL events.
const bpfProgPrefix = "bpf_prog_"

// bpfSymbolizerPlatform is responsible for getting updates from `PERF_RECORD_KSYMBOL`.
// The symbolizer is not ready to use until startMonitor is called to load the symbols.
type bpfSymbolizerPlatform struct {
	records chan *perf.KSymbolRecord
	reader  *perfutil.PerfSidebandReader
	cancel  context.CancelFunc
}

// loadBPFPrograms enumerates all loaded BPF programs via the bpf syscall and
// builds a sorted bpfSymbolTable from their JIT symbol addresses and sizes.
// Only symbols with the "bpf_prog_" prefix are included; trampolines and
// dispatchers are intentionally excluded because they are not visible at
// initial scan time and would cause misattribution.
func (s *bpfSymbolizer) loadBPFPrograms() error {
	symbols := []bpfSymbol{}

	id := ebpf.ProgramID(0)
	for {
		var err error
		id, err = ebpf.ProgramGetNextID(id)
		if err != nil {
			break
		}

		prog, err := ebpf.NewProgramFromID(id)
		if err != nil {
			// Program may have been unloaded between listing and opening.
			continue
		}

		info, err := prog.Info()
		prog.Close()
		if err != nil {
			continue
		}

		addrs, ok := info.JitedKsymAddrs()
		if !ok || len(addrs) == 0 {
			continue
		}

		lens, _ := info.JitedFuncLens()

		// The kernel names BPF JIT symbols as "bpf_prog_<tag>_<name>".
		name := bpfProgPrefix + info.Tag + "_" + info.Name

		for i, addr := range addrs {
			sym := bpfSymbol{
				address: libpf.Address(addr),
				name:    name,
			}

			if i < len(lens) {
				sym.size = lens[i]
			}

			symbols = append(symbols, sym)
		}
	}

	slices.SortFunc(symbols, func(a, b bpfSymbol) int {
		return cmp.Compare(a.address, b.address)
	})

	old := s.table.Load()
	s.table.Store(&bpfSymbolTable{
		generation: old.symbolGeneration().next(),
		symbols:    symbols,
	})

	return nil
}

// startMonitor starts the update monitoring and loads bpf symbols.
func (s *bpfSymbolizer) startMonitor(ctx context.Context, onlineCPUs []int) error {
	ctx, s.platform.cancel = context.WithCancel(ctx)

	err := s.subscribe(ctx, onlineCPUs)
	if err != nil {
		return err
	}

	err = s.loadBPFPrograms()
	if err != nil {
		return err
	}

	go s.reloadWorker(ctx)

	return nil
}

// subscribe subscribes to updates for bpf symbols via `PERF_RECORD_KSYMBOL`.
func (s *bpfSymbolizer) subscribe(ctx context.Context, onlineCPUs []int) error {
	s.platform.records = make(chan *perf.KSymbolRecord)

	reader, err := perfutil.Start(ctx, onlineCPUs, perfutil.Config{
		Name: "ksymbol",
		Configure: func(attr *perf.Attr) {
			attr.Options.KSymbol = true
		},
		OnRecord: s.handleKSymbolRecord,
	})
	if err != nil {
		return err
	}
	s.platform.reader = reader

	return nil
}

// handleKSymbolRecord forwards a single perf record to the reload worker.
func (s *bpfSymbolizer) handleKSymbolRecord(ctx context.Context, record perf.Record) {
	switch ksymbol := record.(type) {
	case *perf.LostRecord:
		// nil as a sentinel value to indicate lost events. Whenever this happens
		// we trigger a full re-scan of existing bpf programs to prevent data loss.
		select {
		case s.platform.records <- nil:
		case <-ctx.Done():
		}
	case *perf.KSymbolRecord:
		if ksymbol.Type != unix.PERF_RECORD_KSYMBOL_TYPE_BPF {
			return
		}

		select {
		case s.platform.records <- ksymbol:
		case <-ctx.Done():
		}
	default:
		log.Debugf("Unexpected perf record type: %T", record)
	}
}

// reloadWorker is the goroutine handling the reloads of the bpf symbols.
func (s *bpfSymbolizer) reloadWorker(ctx context.Context) {
	noTimeout := make(<-chan time.Time)
	nextReload := noTimeout
	for {
		select {
		case <-nextReload:
			if err := s.loadBPFPrograms(); err == nil {
				log.Debugf("Kernel symbols reloaded")
				nextReload = noTimeout
			} else {
				log.Warnf("Failed to reload kernel symbols: %v", err)
				nextReload = time.After(time.Second)
			}
		case record := <-s.platform.records:
			if err := s.handleBPFUpdate(record); err != nil {
				log.Warnf("Error handling bpf ksymbol update: %v", err)
				nextReload = time.After(time.Second)
			}
		case <-ctx.Done():
			return
		}
	}
}

// handleBPFUpdate handles the update record from perf events.
func (s *bpfSymbolizer) handleBPFUpdate(record *perf.KSymbolRecord) error {
	if record == nil {
		return errors.New("lost events detected")
	}

	// Only track bpf_prog_* symbols. Trampolines, dispatchers, and other
	// BPF-tagged symbols are excluded because they are not present at initial
	// scan time and would cause misattribution.
	if !strings.HasPrefix(record.Name, bpfProgPrefix) {
		return nil
	}

	if record.Flags&unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER != 0 {
		s.removeBPFSymbol(libpf.Address(record.Addr))
		return nil
	}

	s.addBPFSymbol(libpf.Address(record.Addr), record.Name, record.Len)

	return nil
}

// close frees resources associated with bpfSymbolizer.
func (s *bpfSymbolizer) close() {
	// Cancel the context first so reloadWorker observes ctx.Done() and exits.
	// The reader stops and tears down its own events in Close().
	if s.platform.cancel != nil {
		s.platform.cancel()
	}
	if s.platform.reader != nil {
		s.platform.reader.Close()
	}
}
