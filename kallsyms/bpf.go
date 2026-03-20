// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms // import "go.opentelemetry.io/ebpf-profiler/kallsyms"

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/elastic/go-perf"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/sys/unix"
)

type bpfSymbol struct {
	address libpf.Address
	name    string
}

// bpfSymbolizer is responsible for getting updates from `PERF_RECORD_KSYMBOL`.
// The symbolizer is not ready to use until startMonitor is called to load the symbols.
type bpfSymbolizer struct {
	records chan *perf.KSymbolRecord
	events  []*perf.Event
	cancel  context.CancelFunc
	module  atomic.Pointer[Module]
}

// Module returns the [Module] with bpf symbols in it.
// It returns nil until startMonitor is called or if there are no bpf symbols.
func (s *bpfSymbolizer) Module() *Module {
	return s.module.Load()
}

// loadBPFPrograms enumerates all loaded BPF programs via bpf syscall
// and builds a Module from their JIT symbol addresses and names.
func (s *bpfSymbolizer) loadBPFPrograms() error {
	var symbols []bpfSymbol
	minAddr := uint64(0)

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

		// The kernel names BPF JIT symbols as "bpf_prog_<tag>_<name>".
		name := "bpf_prog_" + info.Tag + "_" + info.Name

		for _, addr := range addrs {
			a := uint64(addr)
			if a < minAddr || minAddr == 0 {
				minAddr = a
			}
			symbols = append(symbols, bpfSymbol{
				address: libpf.Address(a),
				name:    name,
			})
		}
	}

	if len(symbols) == 0 {
		s.module.Store(nil)
		return nil
	}

	mod := &Module{
		start: libpf.Address(minAddr),
	}
	mod.addName("bpf")

	for _, sym := range symbols {
		mod.symbols = append(mod.symbols, symbol{
			offset: uint32(sym.address - mod.start),
			index:  mod.addName(sym.name),
		})
	}

	mod.finish()

	s.module.Store(mod)

	return nil
}

// startMonitor starts the update monitoring and loads bpf symbols.
func (s *bpfSymbolizer) startMonitor(ctx context.Context, onlineCPUs []int) error {
	ctx, s.cancel = context.WithCancel(ctx)

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
	attr := new(perf.Attr)
	perf.Dummy.Configure(attr)
	attr.Options.KSymbol = true
	attr.SetWakeupWatermark(1)

	s.records = make(chan *perf.KSymbolRecord)

	for _, cpu := range onlineCPUs {
		event, err := perf.Open(attr, perf.AllThreads, cpu, nil)
		if err != nil {
			return err
		}

		s.events = append(s.events, event)

		err = event.MapRing()
		if err != nil {
			return err
		}

		err = event.Enable()
		if err != nil {
			return err
		}

		go func(event *perf.Event) {
			for {
				record, err := event.ReadRecord(ctx)
				if err != nil {
					if ctx.Err() != nil {
						return
					}

					log.Errorf("Failed to read perf event: %v", err)
					continue
				}

				switch ksymbol := record.(type) {
				case *perf.LostRecord:
					// nil as a sentinel value to indicate lost events
					select {
					case s.records <- nil:
					case <-ctx.Done():
						return
					}
				case *perf.KSymbolRecord:
					if ksymbol.Type != unix.PERF_RECORD_KSYMBOL_TYPE_BPF {
						continue
					}

					select {
					case s.records <- ksymbol:
					case <-ctx.Done():
						return
					}
				}
			}
		}(event)
	}

	return nil
}

// reloadWorker is the goroutine handling the reloads of the bpf symbols.
func (s *bpfSymbolizer) reloadWorker(ctx context.Context) {
	noTimeout := make(<-chan time.Time)
	nextKallsymsReload := noTimeout
	for {
		select {
		case <-nextKallsymsReload:
			if err := s.loadBPFPrograms(); err == nil {
				log.Debugf("Kernel symbols reloaded")
				nextKallsymsReload = noTimeout
			} else {
				log.Warnf("Failed to reload kernel symbols: %v", err)
				nextKallsymsReload = time.After(time.Second)
			}
		case record := <-s.records:
			if err := s.handleBPFUpdate(record); err != nil {
				log.Warnf("Error handling bpf ksymbol update: %v", err)
				nextKallsymsReload = time.After(time.Second)
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

	mod := s.module.Load()
	if mod == nil {
		// Unlikely to be triggered as some bpf programs are loaded by the tracer.
		return errors.New("first bpf symbol being added")
	}

	addr := libpf.Address(record.Addr)

	if record.Flags&unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER != 0 {
		return s.removeBPFSymbol(mod, addr)
	}

	return s.addBPFSymbol(mod, addr, record.Name)
}

// addBPFSymbol handles adding a new BPF symbol to the module.
func (s *bpfSymbolizer) addBPFSymbol(mod *Module, addr libpf.Address, name string) error {
	var replacement *Module

	if addr < mod.start {
		// New symbol is below the current module start. Shift all existing
		// offsets up by the difference and set the new start address.
		replacement = mod.replacement()

		delta := uint32(mod.start - addr)
		for i := range replacement.symbols {
			replacement.symbols[i].offset += delta
		}
		replacement.start = addr

		replacement.symbols = append(replacement.symbols, symbol{
			offset: 0,
			index:  replacement.addName(name),
		})
	} else {
		// If we can find the exact symbol, it's a benign race.
		// A race is possible for events that were buffered while a full parsing happened.
		existing, off, err := mod.LookupSymbolByAddress(addr)
		if err != nil || off > 0 || existing != name {
			replacement = mod.replacement()

			replacement.symbols = append(replacement.symbols, symbol{
				offset: uint32(addr - replacement.start),
				index:  replacement.addName(name),
			})
		}
	}

	if replacement != nil {
		replacement.finish()
		s.module.Store(replacement)
	}

	return nil
}

// removeBPFSymbol handles removing a BPF symbol from the module.
func (s *bpfSymbolizer) removeBPFSymbol(mod *Module, addr libpf.Address) error {
	// If we can find the exact symbol, remove it. If we can't, it's a benign race.
	// A race is possible for events that were buffered while a full parsing happened.
	removeIdx := slices.IndexFunc(mod.symbols, func(sym symbol) bool {
		return sym.offset == uint32(addr-mod.start)
	})
	if removeIdx == -1 {
		return nil
	}

	replacement := mod.replacement()
	replacement.symbols = slices.Delete(replacement.symbols, removeIdx, removeIdx+1)

	if len(replacement.symbols) == 0 {
		// All symbols gone, clear the module.
		s.module.Store(nil)
		return nil
	}

	// If the lowest-address symbol was removed, adjust the module
	// start to the new lowest and shift all offsets down.
	newFirst := replacement.symbols[len(replacement.symbols)-1]
	if newFirst.offset > 0 {
		delta := newFirst.offset
		replacement.start += libpf.Address(delta)
		for i := range replacement.symbols {
			replacement.symbols[i].offset -= delta
		}
	}

	replacement.finish()
	s.module.Store(replacement)

	return nil
}

// Close frees resources associated with bpfSymbolizer.
func (s *bpfSymbolizer) Close() {
	// Cancel the context first so reader goroutines and reloadWorker
	// observe ctx.Done() and exit before we close the perf events.
	if s.cancel != nil {
		s.cancel()
	}

	for _, event := range s.events {
		if err := event.Disable(); err != nil {
			log.Errorf("Failed to disable perf event: %v", err)
		}
		if err := event.Close(); err != nil {
			log.Errorf("Failed to close perf event: %v", err)
		}
	}

	s.events = nil
}
