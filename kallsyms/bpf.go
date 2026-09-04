// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms // import "go.opentelemetry.io/ebpf-profiler/kallsyms"

import (
	"cmp"
	"slices"
	"sync/atomic"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type bpfSymbol struct {
	address libpf.Address
	size    uint32
	name    string
}

// bpfSymbolTable is a sorted (by address) snapshot of all known BPF program
// symbols. It is stored atomically so readers never block writers.
type bpfSymbolTable struct {
	generation Generation
	symbols    []bpfSymbol
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

func (t *bpfSymbolTable) symbolGeneration() Generation {
	if t == nil {
		return makeBPFGeneration(0)
	}
	return t.generation
}

// bpfSymbolizer is responsible for BPF program symbol lookups. Platform-specific
// code may populate and update the table from kernel events.
type bpfSymbolizer struct {
	table    atomic.Pointer[bpfSymbolTable]
	platform bpfSymbolizerPlatform
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

	s.table.Store(&bpfSymbolTable{
		generation: old.symbolGeneration().next(),
		symbols:    newSymbols,
	})
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

	s.table.Store(&bpfSymbolTable{
		generation: old.symbolGeneration().next(),
		symbols:    newSymbols,
	})
}
