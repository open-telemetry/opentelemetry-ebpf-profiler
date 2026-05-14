// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms // import "go.opentelemetry.io/ebpf-profiler/kallsyms"

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/elastic/go-perf"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/sys/unix"
)

// bpfProgPrefix is the prefix the kernel uses for all JIT'd BPF program
// symbols in /proc/kallsyms and PERF_RECORD_KSYMBOL events.
const bpfProgPrefix = "bpf_prog_"

type bpfSymbol struct {
	address libpf.Address
	size    uint32
	name    string
}

// bpfSymbolTable is a sorted (by address) snapshot of all known BPF program
// symbols. It is stored atomically so readers never block writers.
type bpfSymbolTable struct {
	symbols []bpfSymbol
}

// lookup returns the symbol containing addr, or ("", false) if none does.
// A symbol covers [address, address+size).
func (t *bpfSymbolTable) lookup(addr libpf.Address) (string, uint, bool) {
	// Binary search for the last symbol whose address <= addr.
	// BinarySearchFunc returns (index of exact match, true) or
	// (insertion point, false). In both cases the candidate symbol
	// is at the returned index when found, or at index-1 when not found.
	idx, found := slices.BinarySearchFunc(t.symbols, addr, func(sym bpfSymbol, a libpf.Address) int {
		return cmp.Compare(sym.address, a)
	})

	if !found {
		// idx is the insertion point; the last symbol with address <= addr
		// is one position to the left.
		if idx == 0 {
			return "", 0, false
		}
		idx--
	}

	sym := &t.symbols[idx]
	if addr >= sym.address+libpf.Address(sym.size) {
		return "", 0, false
	}

	return sym.name, uint(addr - sym.address), true
}

// bpfSymbolizer is responsible for getting updates from `PERF_RECORD_KSYMBOL`.
// The symbolizer is not ready to use until startMonitor is called to load the symbols.
type bpfSymbolizer struct {
	records chan *perf.KSymbolRecord
	events  []*perf.Event
	cancel  context.CancelFunc
	table   atomic.Pointer[bpfSymbolTable]
	wg      sync.WaitGroup
}

// LookupSymbol resolves addr to a BPF program symbol name and offset.
// Returns ("", 0, false) if no BPF program covers addr.
func (s *bpfSymbolizer) LookupSymbol(addr libpf.Address) (string, uint, bool) {
	t := s.table.Load()
	if t == nil {
		return "", 0, false
	}

	return t.lookup(addr)
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

	s.table.Store(&bpfSymbolTable{symbols: symbols})

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

		s.wg.Add(1)
		go func(event *perf.Event) {
			defer s.wg.Done()
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
					// nil as a sentinel value to indicate lost events. Whenever this happens
					// we trigger a full re-scan of existing bpf programs to prevent data loss.
					select {
					case s.records <- nil:
					case <-ctx.Done():
					}
				case *perf.KSymbolRecord:
					if ksymbol.Type != unix.PERF_RECORD_KSYMBOL_TYPE_BPF {
						continue
					}

					select {
					case s.records <- ksymbol:
					case <-ctx.Done():
					}
				default:
					log.Debugf("Unexpected perf record type: %T", record)
				}

				if ctx.Err() != nil {
					return
				}
			}
		}(event)
	}

	return nil
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
		case record := <-s.records:
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

// addBPFSymbol inserts a new BPF program symbol into the table.
func (s *bpfSymbolizer) addBPFSymbol(addr libpf.Address, name string, size uint32) {
	old := s.table.Load()
	var oldSymbols []bpfSymbol
	if old != nil {
		oldSymbols = old.symbols
	}

	// Check for a benign race: symbol already present with the same name.
	idx, found := slices.BinarySearchFunc(oldSymbols, addr, func(sym bpfSymbol, a libpf.Address) int {
		return cmp.Compare(sym.address, a)
	})
	if found && oldSymbols[idx].name == name {
		return
	}

	// Insert the new symbol into the right position to maintain sorting.
	newSym := bpfSymbol{address: addr, size: size, name: name}
	newSymbols := make([]bpfSymbol, len(oldSymbols)+1)
	copy(newSymbols, oldSymbols[:idx])
	newSymbols[idx] = newSym
	copy(newSymbols[idx+1:], oldSymbols[idx:])

	s.table.Store(&bpfSymbolTable{symbols: newSymbols})
}

// removeBPFSymbol removes a BPF program symbol from the table by address.
func (s *bpfSymbolizer) removeBPFSymbol(addr libpf.Address) {
	old := s.table.Load()
	if old == nil {
		return
	}

	idx, found := slices.BinarySearchFunc(old.symbols, addr, func(sym bpfSymbol, a libpf.Address) int {
		return cmp.Compare(sym.address, a)
	})
	if !found {
		return
	}

	newSymbols := make([]bpfSymbol, len(old.symbols)-1)
	copy(newSymbols, old.symbols[:idx])
	copy(newSymbols[idx:], old.symbols[idx+1:])

	s.table.Store(&bpfSymbolTable{symbols: newSymbols})
}

// Close frees resources associated with bpfSymbolizer.
func (s *bpfSymbolizer) Close() {
	// Cancel the context first so reader goroutines and reloadWorker
	// observe ctx.Done() and exit before we close the perf events.
	if s.cancel != nil {
		s.cancel()
	}
	// We have to wait for all goroutines to exit before closing events,
	// otherwise we're introducing a race that leads to a panic as go-perf
	// may (internally) send on a closed channel.
	s.wg.Wait()

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
