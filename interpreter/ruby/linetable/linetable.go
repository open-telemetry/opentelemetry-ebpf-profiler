// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package linetable reads the succinct instruction index used by 64-bit MRI since Ruby 2.6.
package linetable // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby/linetable"

import (
	"errors"
	"math/bits"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// Lookup returns the zero-based instruction info entry for an instruction position.
// table points to MRI's succ_index_table and size counts the instruction info entries.
func Lookup(mem remotememory.RemoteMemory, table libpf.Address, pos uint64, size uint32) (uint32, error) {
	if table == 0 || pos > 1<<32-1 {
		return 0, errors.New("invalid Ruby instruction index")
	}
	var rank uint64
	if pos < 54 {
		// The first six words each pack nine seven-bit ranks.
		word, err := mem.ReadUint64(table + libpf.Address(pos/9*8))
		if err != nil {
			return 0, err
		}
		rank = word >> (pos % 9 * 7) & 0x7f
	} else {
		// Each 512-position block stores a base rank, packed nine-bit
		// ranks for its word boundaries, and eight bitmap words.
		pos -= 54
		block := table + 48 + libpf.Address(pos/512*80)
		base, err := mem.ReadUint32(block)
		if err != nil {
			return 0, err
		}
		rank = uint64(base)
		i := pos % 512 / 64
		if i != 0 {
			ranks, err := mem.ReadUint64(block + 8)
			if err != nil {
				return 0, err
			}
			rank += ranks >> ((i - 1) * 9) & 0x1ff
		}
		word, err := mem.ReadUint64(block + 16 + libpf.Address(i*8))
		if err != nil {
			return 0, err
		}
		rank += uint64(bits.OnesCount64(word << (63 - pos%64)))
	}
	if rank == 0 || rank > uint64(size) {
		return 0, errors.New("Ruby instruction info index out of range")
	}
	return uint32(rank - 1), nil
}

// Layout holds byte offsets in rb_iseq_constant_body and iseq_insn_info_entry.
type Layout struct {
	BodyEncoded, BodyInsnInfo, BodyInsnInfoSize, BodySuccIndexTable uint16
	InsnInfoEntrySize, InsnInfoLineNo                               uint16
}

// SourceLine reads the source line for a control frame's saved PC.
func SourceLine(mem remotememory.RemoteMemory, body libpf.Address, pc uint64, l Layout) (uint32, error) {
	size, err := mem.ReadUint32(body + libpf.Address(l.BodyInsnInfoSize))
	if err != nil {
		return 0, err
	}
	entries, err := mem.ReadPtr(body + libpf.Address(l.BodyInsnInfo))
	if err != nil {
		return 0, err
	}
	if size == 1 && entries != 0 {
		return mem.ReadUint32(entries + libpf.Address(l.InsnInfoLineNo))
	}
	encoded, err := mem.ReadPtr(body + libpf.Address(l.BodyEncoded))
	if err != nil {
		return 0, err
	}
	table, err := mem.ReadPtr(body + libpf.Address(l.BodySuccIndexTable))
	if err != nil {
		return 0, err
	}
	return IndexedLine(mem, pc, uint64(encoded), table, entries, size, l.InsnInfoEntrySize, l.InsnInfoLineNo)
}

// IndexedLine resolves a saved PC when the caller has already read the iseq body.
func IndexedLine(mem remotememory.RemoteMemory, pc, encoded uint64, table, entries libpf.Address,
	size uint32, entrySize, lineOffset uint16) (uint32, error) {
	if size == 0 || pc < encoded || entries == 0 {
		return 0, errors.New("invalid Ruby instruction sequence")
	}
	// The saved PC points just past the current instruction.
	pos := (pc - encoded) / 8
	if pos != 0 {
		pos--
	}
	index, err := Lookup(mem, table, pos, size)
	if err != nil {
		return 0, err
	}
	return mem.ReadUint32(entries + libpf.Address(uint64(index)*uint64(entrySize)) + libpf.Address(lineOffset))
}
