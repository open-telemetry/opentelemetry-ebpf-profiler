// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms // import "go.opentelemetry.io/ebpf-profiler/kallsyms"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/elastic/go-perf"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/stringutil"
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
	module  atomic.Pointer[Module]
}

// Module returns the [Module] with bpf symbols in it.
// It returns nil until startMonitor is called or if there are no bpf symbols.
func (s *bpfSymbolizer) Module() *Module {
	return s.module.Load()
}

// loadKallsyms loads bpf symbols from /proc/kallsyms.
func (s *bpfSymbolizer) loadKallsyms() error {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return fmt.Errorf("unable to open kallsyms: %v", err)
	}
	defer file.Close()

	return s.updateSymbolsFrom(file)
}

// updateSymbolsFrom parses /proc/kallsyms format data from the reader 'r'.
func (s *bpfSymbolizer) updateSymbolsFrom(r io.Reader) error {
	symbols := []bpfSymbol{}

	minAddr := uint64(0)

	for scanner := bufio.NewScanner(r); scanner.Scan(); {
		// Avoid heap allocation by not using scanner.Text().
		// NOTE: The underlying bytes will change with the next call to scanner.Scan(),
		// so make sure to not keep any references after the end of the loop iteration.
		line := pfunsafe.ToString(scanner.Bytes())

		// Avoid heap allocations here - do not use strings.FieldsN()
		var fields [4]string
		nFields := stringutil.FieldsN(line, fields[:])
		if nFields < 3 {
			return fmt.Errorf("unexpected line in kallsyms: '%s'", line)
		}

		if fields[3] != "[bpf]" {
			continue
		}

		address, err := strconv.ParseUint(fields[0], 16, pointerBits)
		if err != nil {
			return fmt.Errorf("failed to parse address value: '%s'", fields[0])
		}

		if address < minAddr || minAddr == 0 {
			minAddr = address
		}

		// bpf symbols can come out of order, so we cannot build a Module incrementally
		symbols = append(symbols, bpfSymbol{
			address: libpf.Address(address),
			name:    strings.Clone(fields[2]),
		})
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

// startMonitor starts the update monitoring and loads bpf symbols from /proc/kallsyms.
func (s *bpfSymbolizer) startMonitor(ctx context.Context, onlineCPUs []int) error {
	err := s.subscribe(ctx, onlineCPUs)
	if err != nil {
		return err
	}

	err = s.loadKallsyms()
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
		event, err := perf.Open(attr, -1, cpu, nil)
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
			if err := s.loadKallsyms(); err == nil {
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
		return errors.New("first bpf symbol being added")
	}

	var replacement *Module

	addr := libpf.Address(record.Addr)

	if record.Flags&unix.PERF_RECORD_KSYMBOL_FLAGS_UNREGISTER != 0 {
		// If we can find the exact symbol, remove it. If we can't, it's a benign race.
		// A race is possible for events that were buffered while a full parsing happened.
		removeIdx := slices.IndexFunc(mod.symbols, func(sym symbol) bool {
			return sym.offset == uint32(addr-mod.start)
		})
		if removeIdx != -1 {
			replacement = mod.replacement()

			if replacement.symbols[removeIdx].offset == 0 {
				return errors.New("the first symbol is being removed, full re-scan is necessary")
			}

			replacement.symbols = slices.Delete(replacement.symbols, removeIdx, removeIdx+1)
		}
	} else {
		if addr < mod.start {
			return errors.New("new bpf symbol below bpf module start, full re-scan is necessary")
		}

		// If we can't find the exact symbol, add a new one. If we can't, it's a benign race.
		// A race is possible for events that were buffered while a full parsing happened.
		name, off, err := mod.LookupSymbolByAddress(addr)
		if err != nil || off > 0 || name != record.Name {
			replacement = mod.replacement()

			replacement.symbols = append(replacement.symbols, symbol{
				offset: uint32(addr - replacement.start),
				index:  replacement.addName(record.Name),
			})
		}
	}

	if replacement != nil {
		replacement.finish()
		s.module.Store(replacement)
	}

	return nil
}

// Close frees resources associated with bpfSymbolizer.
func (s *bpfSymbolizer) Close() {
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
