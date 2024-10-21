// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package stackdeltatypes provides types used to represent stack delta information as constructed
// by `nativeunwind.GetIntervalStructures` This information is a post-processed form of the
// stack delta information that is used in all relevant packages.
package stackdeltatypes // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"

// #include "../../support/ebpf/stackdeltatypes.h"
import "C"

const (
	// ABI is the current binary compatibility version. It is incremented
	// if struct IntervalData, struct StackDelta or the meaning of their contents
	// changes, and can be used to determine if the data is compatible
	ABI = 15

	// MinimumGap determines the minimum number of alignment bytes needed
	// in order to keep the created STOP stack delta between functions
	MinimumGap = 15

	// UnwindOpcodes from the C header file
	UnwindOpcodeCommand   uint8 = C.UNWIND_OPCODE_COMMAND
	UnwindOpcodeBaseCFA   uint8 = C.UNWIND_OPCODE_BASE_CFA
	UnwindOpcodeBaseSP    uint8 = C.UNWIND_OPCODE_BASE_SP
	UnwindOpcodeBaseFP    uint8 = C.UNWIND_OPCODE_BASE_FP
	UnwindOpcodeBaseLR    uint8 = C.UNWIND_OPCODE_BASE_LR
	UnwindOpcodeBaseReg   uint8 = C.UNWIND_OPCODE_BASE_REG
	UnwindOpcodeFlagDeref uint8 = C.UNWIND_OPCODEF_DEREF

	// UnwindCommands from the C header file
	UnwindCommandInvalid int32 = C.UNWIND_COMMAND_INVALID
	UnwindCommandStop    int32 = C.UNWIND_COMMAND_STOP
	UnwindCommandPLT     int32 = C.UNWIND_COMMAND_PLT
	UnwindCommandSignal  int32 = C.UNWIND_COMMAND_SIGNAL

	// UnwindDeref handling from the C header file
	UnwindDerefMask       int32 = C.UNWIND_DEREF_MASK
	UnwindDerefMultiplier int32 = C.UNWIND_DEREF_MULTIPLIER

	// UnwindHintNone indicates that no flags are set.
	UnwindHintNone uint8 = 0
	// UnwindHintKeep flags important intervals that should not be removed
	// (e.g. has CALL/SYSCALL assembly opcode, or is part of function prologue)
	UnwindHintKeep uint8 = 1
	// UnwindHintGap indicates that the delta marks function end
	UnwindHintGap uint8 = 4
)

// UnwindInfo contains the data needed to unwind PC, SP and FP
type UnwindInfo struct {
	Opcode, FPOpcode, MergeOpcode uint8

	Param, FPParam int32
}

// UnwindInfoInvalid is the stack delta info indicating invalid or unsupported PC.
var UnwindInfoInvalid = UnwindInfo{Opcode: UnwindOpcodeCommand, Param: UnwindCommandInvalid}

// UnwindInfoStop is the stack delta info indicating root function of a stack.
var UnwindInfoStop = UnwindInfo{Opcode: UnwindOpcodeCommand, Param: UnwindCommandStop}

// UnwindInfoSignal is the stack delta info indicating signal return frame.
var UnwindInfoSignal = UnwindInfo{Opcode: UnwindOpcodeCommand, Param: UnwindCommandSignal}

// UnwindInfoFramePointerX64 contains the description to unwind a x86-64 frame pointer frame.
var UnwindInfoFramePointerX64 = UnwindInfo{
	Opcode:   UnwindOpcodeBaseFP,
	Param:    16,
	FPOpcode: UnwindOpcodeBaseCFA,
	FPParam:  -16,
}

// UnwindInfoLR contains the description to unwind arm function without frame (Link Register only)
var UnwindInfoLR = UnwindInfo{
	Opcode:   UnwindOpcodeBaseSP,
	FPOpcode: UnwindOpcodeBaseLR,
}

// StackDelta defines the start address for the delta interval, along with
// the unwind information.
type StackDelta struct {
	Address uint64
	Hints   uint8
	Info    UnwindInfo
}

// StackDeltaArray defines an address space where consecutive entries establish
// intervals for the stack deltas
type StackDeltaArray []StackDelta

// IntervalData contains everything that a userspace agent needs to have
// to populate eBPF maps for the kernel-space native unwinder to do its job:
type IntervalData struct {
	// Deltas contains all stack deltas for a single binary.
	// Two consecutive entries describe an interval.
	Deltas StackDeltaArray
}

// AddEx adds a new stack delta to the array.
func (deltas *StackDeltaArray) AddEx(delta StackDelta, sorted bool) {
	num := len(*deltas)
	if delta.Info.Opcode == UnwindOpcodeCommand {
		// FP information is invalid/unused for command opcodes.
		// But DWARF info often leaves bogus data there, so resetting it
		// reduces the number of unique Info contents generated.
		delta.Info.FPOpcode = UnwindOpcodeCommand
		delta.Info.FPParam = UnwindCommandInvalid
	}
	if num > 0 && sorted {
		prev := &(*deltas)[num-1]
		if prev.Hints&UnwindHintGap != 0 && prev.Address+MinimumGap >= delta.Address {
			// The previous opcode is end-of-function marker, and
			// the gap is not large. Reduce deltas by overwriting it.
			if num <= 1 || (*deltas)[num-2].Info != delta.Info {
				*prev = delta
				return
			}
			// The delta before end-of-function marker is same as
			// what is being inserted now. Overwrite that.
			prev = &(*deltas)[num-2]
			*deltas = (*deltas)[:num-1]
		}
		if prev.Info == delta.Info {
			prev.Hints |= delta.Hints & UnwindHintKeep
			return
		}
		if prev.Address == delta.Address {
			*prev = delta
			return
		}
	}
	*deltas = append(*deltas, delta)
}

// Add adds a new stack delta from a sorted source.
func (deltas *StackDeltaArray) Add(delta StackDelta) {
	deltas.AddEx(delta, true)
}

// PackDerefParam compresses pre- and post-dereference parameters to single value
func PackDerefParam(preDeref, postDeref int32) (int32, bool) {
	if postDeref < 0 || postDeref > 0x20 || postDeref%UnwindDerefMultiplier != 0 {
		return 0, false
	}
	return preDeref + postDeref/UnwindDerefMultiplier, true
}

// UnpackDerefParam splits the pre- and post-dereference parameters from single value
func UnpackDerefParam(param int32) (preDeref, postDeref int32) {
	return param &^ UnwindDerefMask, (param & UnwindDerefMask) * UnwindDerefMultiplier
}
