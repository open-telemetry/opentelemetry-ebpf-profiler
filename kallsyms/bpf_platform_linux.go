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
	"sync"
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

// bpfSymbolizerPlatform is responsible for getting updates from `PERF_RECORD_KSYMBOL`.
// The symbolizer is not ready to use until startMonitor is called to load the symbols.
type bpfSymbolizerPlatform struct {
	records chan *perf.KSymbolRecord
	events  []*perf.Event
	cancel  context.CancelFunc
	wg      sync.WaitGroup
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
	attr := new(perf.Attr)
	perf.Dummy.Configure(attr)
	attr.Options.KSymbol = true
	attr.SetWakeupWatermark(1)

	s.platform.records = make(chan *perf.KSymbolRecord)

	for _, cpu := range onlineCPUs {
		event, err := perf.Open(attr, perf.AllThreads, cpu, nil)
		if err != nil {
			return err
		}

		s.platform.events = append(s.platform.events, event)

		err = event.MapRing()
		if err != nil {
			return err
		}

		err = event.Enable()
		if err != nil {
			return err
		}

		s.platform.wg.Go(func() {
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
					case s.platform.records <- nil:
					case <-ctx.Done():
					}
				case *perf.KSymbolRecord:
					if ksymbol.Type != unix.PERF_RECORD_KSYMBOL_TYPE_BPF {
						continue
					}

					select {
					case s.platform.records <- ksymbol:
					case <-ctx.Done():
					}
				default:
					log.Debugf("Unexpected perf record type: %T", record)
				}

				if ctx.Err() != nil {
					return
				}
			}
		})
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
	// Cancel the context first so reader goroutines and reloadWorker
	// observe ctx.Done() and exit before we close the perf events.
	if s.platform.cancel != nil {
		s.platform.cancel()
	}
	// We have to wait for all goroutines to exit before closing events,
	// otherwise we're introducing a race that leads to a panic as go-perf
	// may (internally) send on a closed channel.
	s.platform.wg.Wait()

	for _, event := range s.platform.events {
		if err := event.Disable(); err != nil {
			log.Errorf("Failed to disable perf event: %v", err)
		}
		if err := event.Close(); err != nil {
			log.Errorf("Failed to close perf event: %v", err)
		}
	}

	s.platform.events = nil
}
