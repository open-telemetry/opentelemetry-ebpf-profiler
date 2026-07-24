// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package stackdeltatypes provides types used to represent stack delta information as constructed
// by `nativeunwind.GetIntervalStructures` This information is a post-processed form of the
// stack delta information that is used in all relevant packages.
package stackdeltatypes // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"

import (
	"cmp"
	"slices"

	"go.opentelemetry.io/ebpf-profiler/support"
)

// UnwindInfo contains the data needed to unwind PC, SP and FP
type UnwindInfo = support.UnwindInfo

// UnwindInfoInvalid is the stack delta info indicating invalid or unsupported PC.
var UnwindInfoInvalid = UnwindInfo{Flags: support.UnwindFlagCommand,
	Param: support.UnwindCommandInvalid}

// UnwindInfoStop is the stack delta info indicating root function of a stack.
var UnwindInfoStop = UnwindInfo{Flags: support.UnwindFlagCommand,
	Param: support.UnwindCommandStop}

// UnwindInfoSignal is the stack delta info indicating signal return frame.
var UnwindInfoSignal = UnwindInfo{Flags: support.UnwindFlagCommand,
	Param: support.UnwindCommandSignal}

// UnwindInfoFramePointer contains the description to unwind a frame pointer frame.
var UnwindInfoFramePointer = UnwindInfo{Flags: support.UnwindFlagCommand,
	Param: support.UnwindCommandFramePointer,
}

// UnwindInfoLR contains the description to unwind ARM64 function without a frame (LR only)
var UnwindInfoLR = UnwindInfo{
	BaseReg:    support.UnwindRegSp,
	AuxBaseReg: support.UnwindRegLr,
}

// StackDelta defines the delta from a basic block start, along with the unwind information.
type StackDelta struct {
	Offset uint32
	Info   UnwindInfo
}

// StackDeltaArray defines an address space where consecutive entries establish
// intervals for the stack deltas
type StackDeltaArray []StackDelta

// BasicBlock defines a code area with its start deltas (e.g. ELF FDE or Golang function).
type BasicBlock struct {
	Start  uint64
	End    uint64
	Deltas StackDeltaArray
}

// IntervalData contains everything that a userspace agent needs to have
// to populate eBPF maps for the kernel-space native unwinder to do its job:
type IntervalData struct {
	// NumDeltas is the number of all deltas in all basic blocks.
	NumDeltas uint32
	// Blocks contains all basic blocks of an executable.
	Blocks []*BasicBlock
}

// AddEx adds a new stack delta to the array.
func (deltas *StackDeltaArray) Add(offset uint32, info UnwindInfo) {
	if info.Flags&support.UnwindFlagCommand != 0 {
		// FP information is invalid/unused for command opcodes.
		// But DWARF info often leaves bogus data there, so resetting it
		// reduces the number of unique Info contents generated.
		info = UnwindInfo{
			Flags: support.UnwindFlagCommand,
			Param: info.Param,
		}
	}
	if num := len(*deltas); num > 0 {
		// Remove duplicates
		if (*deltas)[num-1].Info == info {
			return
		}
	}

	*deltas = append(*deltas, StackDelta{Offset: offset, Info: info})
}

// Add inserts a new basic block to the interval data
func (intervals *IntervalData) Add(bb BasicBlock) {
	if len(intervals.Blocks) > 0 && len(bb.Deltas) == 1 {
		lastBlock := intervals.Blocks[len(intervals.Blocks)-1]
		if len(lastBlock.Deltas) == 1 && bb.Deltas[0] == lastBlock.Deltas[0] &&
			bb.Start-lastBlock.End < 16 {
			// Merge consecutive identical single delta basic blocks
			lastBlock.End = bb.End
			return
		}
	}
	intervals.NumDeltas += uint32(len(bb.Deltas))
	intervals.Blocks = append(intervals.Blocks, &bb)
}

// Find searches the matching basic block index from the interval data
func (intervals *IntervalData) FindIndex(addr uint64) int {
	idx, ok := slices.BinarySearchFunc(intervals.Blocks, addr, func(bb *BasicBlock, addr uint64) int {
		return cmp.Compare(bb.Start, addr)
	})
	if !ok {
		if idx == 0 {
			return -1
		}
		idx--
	}
	bb := intervals.Blocks[idx]
	if addr >= bb.Start && addr < bb.End {
		return idx
	}
	return -1
}

// Find searches the matching basic block from the interval data
func (intervals *IntervalData) Find(addr uint64) *BasicBlock {
	if idx := intervals.FindIndex(addr); idx >= 0 {
		return intervals.Blocks[idx]
	}
	return nil
}

// Sort sorts the stack deltas.
func (intervals *IntervalData) Sort() {
	slices.SortFunc(intervals.Blocks, func(a, b *BasicBlock) int {
		return cmp.Compare(a.Start, b.Start)
	})
}

// PackDerefParam compresses pre- and post-dereference parameters to single value
func PackDerefParam(preDeref, postDeref int32) (int32, bool) {
	if postDeref < 0 || postDeref > 0x20 ||
		postDeref%support.UnwindDerefMultiplier != 0 {
		return 0, false
	}
	return preDeref + postDeref/support.UnwindDerefMultiplier, true
}

// UnpackDerefParam splits the pre- and post-dereference parameters from single value
func UnpackDerefParam(param int32) (preDeref, postDeref int32) {
	return param &^ support.UnwindDerefMask,
		(param & support.UnwindDerefMask) * support.UnwindDerefMultiplier
}
