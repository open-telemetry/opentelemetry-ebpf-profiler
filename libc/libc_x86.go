// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libc // import "go.opentelemetry.io/ebpf-profiler/libc"

import (
	"errors"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"golang.org/x/arch/x86/x86asm"
)

func extractTSDInfoX86(code []byte) (TSDInfo, error) {
	it := amd.NewInterpreterWithCode(code)
	key := it.Regs.Get(amd.RDI)
	_, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.RET
	})
	if err != nil {
		return TSDInfo{}, err
	}
	res := it.Regs.Get(amd.RAX)
	var (
		multiplier  = e.NewImmediateCapture("multiplier")
		multiplier2 = e.NewImmediateCapture("multiplier2")
		offset      = e.NewImmediateCapture("offset")
	)

	expected := e.Mem8(
		e.Add(
			e.Mem8(
				e.Add(
					e.MemWithSegment8(x86asm.FS, e.Imm(0)),
					offset,
				),
			),
			e.Multiply(
				e.ZeroExtend32(key),
				multiplier),
		),
	)
	if res.Match(expected) {
		return TSDInfo{
			Offset:     int16(offset.CapturedValue()),
			Multiplier: uint8(multiplier.CapturedValue()),
			Indirect:   1,
		}, nil
	}
	expected = e.Mem8(
		e.Add(
			e.MemWithSegment8(x86asm.FS, e.Imm(0x10)),
			e.Multiply(e.ZeroExtend32(key), multiplier),
			offset,
		),
	)
	if res.Match(expected) {
		return TSDInfo{
			Offset:     int16(offset.CapturedValue()),
			Multiplier: uint8(multiplier.CapturedValue()),
			Indirect:   0,
		}, nil
	}
	expected = e.Mem8(
		e.Add(
			e.MemWithSegment8(x86asm.FS, e.Imm(0x10)),
			e.Multiply(
				e.ZeroExtend32(e.Add(key, multiplier2)),
				multiplier,
			),
			offset,
		),
	)
	if res.Match(expected) {
		return TSDInfo{
			Offset: int16(multiplier.CapturedValue()*multiplier2.CapturedValue() +
				offset.CapturedValue()),
			Multiplier: uint8(multiplier.CapturedValue()),
			Indirect:   0,
		}, nil
	}
	return TSDInfo{}, errors.New("could not extract tsdInfo amd")
}

// extractDTVInfoX86 analyzes __tls_get_addr to find the DTV offset from FS base
func extractDTVInfoX86(code []byte) (DTVInfo, error) {
	it := amd.NewInterpreterWithCode(code)

	// __tls_get_addr takes a tls_index struct in RDI
	tls_index := it.Regs.Get(amd.RDI)
	module_id := e.Mem8(tls_index)
	tls_offset := e.Mem8(e.Add(tls_index, e.Imm(8)))

	// Execute until RET
	_, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.RET
	})
	if err != nil {
		return DTVInfo{}, err
	}

	result := it.Regs.Get(amd.RAX)

	// Capture variables
	var (
		dtvOffset  = e.NewImmediateCapture("dtvOffset")
		entryWidth = e.NewImmediateCapture("entryWidth")
	)

	// Pattern 1: glibc - Direct DTV access
	expected := e.Add(
		e.Mem8(
			e.Add(
				e.MemWithSegment8(x86asm.FS, dtvOffset),
				e.Multiply(module_id, entryWidth),
			),
		),
		tls_offset,
	)

	if result.Match(expected) {
		return DTVInfo{
			Offset:     int64(dtvOffset.CapturedValue()),
			EntryWidth: uint32(entryWidth.CapturedValue()),
			Indirect:   0,
		}, nil
	}

	// Pattern 2: musl - The thread pointer itself might be represented differently
	// Since FS:0 is the thread pointer, and DTV is at offset from it
	thread_ptr := e.MemWithSegment8(x86asm.FS, e.Imm(0))
	dtv_ptr := e.Mem8(e.Add(thread_ptr, dtvOffset))

	expected = e.Add(
		tls_offset,
		e.Mem8(
			e.Add(
				dtv_ptr,
				e.Multiply(module_id, entryWidth),
			),
		),
	)

	if result.Match(expected) {
		return DTVInfo{
			Offset:     int64(dtvOffset.CapturedValue()),
			EntryWidth: uint32(entryWidth.CapturedValue()),
			Indirect:   1,
		}, nil
	}

	// Pattern 3: Reverse addition order
	expected = e.Add(
		e.Mem8(
			e.Add(
				dtv_ptr,
				e.Multiply(module_id, entryWidth),
			),
		),
		tls_offset,
	)

	if result.Match(expected) {
		return DTVInfo{
			Offset:     int64(dtvOffset.CapturedValue()),
			EntryWidth: uint32(entryWidth.CapturedValue()),
			Indirect:   1,
		}, nil
	}

	// Pattern 4: Maybe the scale is encoded in the memory operand differently
	// Try without explicit multiply
	expected = e.Add(
		tls_offset,
		e.Mem8(
			e.Add(
				e.Mem8(e.Add(thread_ptr, dtvOffset)),
				e.Multiply(e.ZeroExtend32(module_id), entryWidth),
			),
		),
	)

	if result.Match(expected) {
		return DTVInfo{
			Offset:     int64(dtvOffset.CapturedValue()),
			EntryWidth: uint32(entryWidth.CapturedValue()),
			Indirect:   1,
		}, nil
	}

	return DTVInfo{}, errors.New("could not extract DTV info: no matching pattern found")
}
