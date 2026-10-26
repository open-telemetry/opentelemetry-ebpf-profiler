// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import (
	"errors"
	"fmt"

	"golang.org/x/arch/x86/x86asm"

	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	npsr "go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
)

// ExtractTLSOffset scans through x86_64 assembly code looking for MOV instructions
// that access Thread Local Storage (TLS) via the FS segment register.
// It handles three common patterns:
//  1. Direct FS-relative addressing: MOV reg, FS:[offset]
//  2. Register-based addressing: MOV $offset, reg; MOV reg, FS:(reg)
//  3. RIP-relative addressing: MOV 0x...(RIP), reg; MOV reg, FS:(reg)
//
// The function returns the TLS offset found, or an error if no valid pattern is detected.
// For RIP-relative addressing, the file parameter can be provided to resolve memory references.
// If file is nil, RIP-relative memory dereferencing will be skipped.
func ExtractTLSOffset(code []byte, codeAddress uint64, file *pfelf.File) (int32, error) {
	offset := e.NewImmediateCapture("offset")
	it := NewInterpreterWithCodeAt(code, e.Imm(codeAddress))

	for {
		op, err := it.Step()
		if err != nil {
			break
		}
		if op.Op != x86asm.MOV {
			continue
		}
		mem, ok := op.Args[1].(x86asm.Mem)
		if !ok || mem.Segment != x86asm.FS {
			continue
		}
		// Pattern 1: Direct FS-relative addressing
		// Example: MOV rax, FS:[0xfffffffffffffff8]
		if mem.Base == 0 {
			return validateTLSOffset(int32(mem.Disp))
		}
		// Pattern 2 & 3: Register-based or RIP-relative addressing
		// Example: MOV $0xfffffffffffffff8, rcx; MOV rax, FS:(rcx)
		// or: MOV 0x40b9af9(RIP), rcx; MOV rax, FS:(rcx)
		// The interpreter handles RIP-relative addressing transparently,
		// resolving it to a virtual memory address.
		actual := it.Regs.GetX86(mem.Base)
		if actual.Match(offset) {
			return validateTLSOffset(int32(offset.CapturedValue()))
		}
		// Pattern 3 continued: If the register value is a memory reference,
		// read from the file to resolve it
		if file != nil {
			addr := e.NewImmediateCapture("addr")
			if actual.Match(e.Mem8(addr)) {
				valueBytes, err := file.VirtualMemory(int64(addr.CapturedValue()), 8, 8)
				if err != nil {
					continue
				}
				// Read the 8-byte value as int64 (little-endian)
				value := int64(npsr.Uint64(valueBytes, 0))
				return validateTLSOffset(int32(value))
			}
		}
	}
	return 0, fmt.Errorf("could not find FS-relative MOV instruction with valid TLS offset")
}

// ExtractTLSSlot scans through x86_64 assembly code looking for TLS accesses
// through the GOT, as used in shared libraries. It handles three patterns:
//  1. Initial-exec: MOV reg, [RIP+slot]; MOV reg, FS:[reg+disp]
//  2. General/local-dynamic: LEA RDI, [RIP+slot]; CALL __tls_get_addr; MOV reg, [RAX+disp]
//  3. TLS descriptor: LEA RAX, [RIP+slot]; CALL [RAX]; MOV reg, FS:[RAX+disp]
//
// The function returns the address of the GOT slot and the displacement the
// code adds to the value it resolves to.
func ExtractTLSSlot(code []byte, codeAddress uint64) (slot uint64, disp int64, err error) {
	capture := e.NewImmediateCapture("slot")
	it := NewInterpreterWithCodeAt(code, e.Imm(codeAddress))
	called := false
	viaDescriptor := false
	// Register holding the call result, or 0 if unknown
	var offReg Reg

	for {
		regs := it.Regs
		op, err := it.Step()
		if err != nil {
			break
		}
		// Untracked writes to the result register invalidate it
		off := offReg
		if called && writesFirstOperand(op.Op) {
			if dst, ok := op.Args[0].(x86asm.Reg); ok && regMappingFor(dst).idx == offReg {
				offReg = 0
			}
		}
		switch op.Op {
		case x86asm.CALL:
			if called {
				return 0, 0, errors.New("unexpected call after TLS slot lookup")
			}
			// __tls_get_addr takes its argument in RDI, also with -fno-plt.
			// Example: CALL [RAX] for a TLS descriptor
			argReg := x86asm.RDI
			if mem, ok := op.Args[0].(x86asm.Mem); ok &&
				mem.Base != 0 && mem.Base != x86asm.RIP {
				argReg = mem.Base
			}
			if regs.GetX86(argReg).Match(capture) {
				slot = capture.CapturedValue()
				called = true
				viaDescriptor = argReg != x86asm.RDI
				offReg = RAX
			}
		case x86asm.LEA:
			// LEA reg, [off+imm]
			dst, dstOk := op.Args[0].(x86asm.Reg)
			mem, memOk := op.Args[1].(x86asm.Mem)
			if called && off != 0 && dstOk && memOk && mem.Segment == 0 && mem.Index == 0 &&
				mem.Base != 0 && regMappingFor(mem.Base).idx == off {
				disp += mem.Disp
				offReg = regMappingFor(dst).idx
			}
		case x86asm.ADD, x86asm.SUB:
			// ADD off, imm or SUB off, imm
			dst, dstOk := op.Args[0].(x86asm.Reg)
			imm, immOk := op.Args[1].(x86asm.Imm)
			if called && off != 0 && dstOk && immOk && regMappingFor(dst).idx == off {
				if op.Op == x86asm.SUB {
					disp -= int64(imm)
				} else {
					disp += int64(imm)
				}
				offReg = off
			}
		case x86asm.MOV:
			mem, ok := op.Args[1].(x86asm.Mem)
			if !ok || mem.Base == 0 {
				continue
			}
			// Pattern 2 & 3: access through the call result
			// Example: MOV rax, [rax+0x8]
			if called && off != 0 && regMappingFor(mem.Base).idx == off {
				if mem.Index != 0 || (mem.Segment == x86asm.FS) != viaDescriptor {
					return 0, 0, fmt.Errorf("unexpected access to TLS call result: %v", op)
				}
				return slot, disp + mem.Disp, nil
			}
			// Pattern 1: FS-relative access with the offset from the GOT
			// Example: MOV 0x2ecd(RIP), rax; MOV rax, FS:(rax)
			if !called && mem.Segment == x86asm.FS &&
				regs.GetX86(mem.Base).Match(e.Mem8(capture)) {
				return capture.CapturedValue(), int64(int32(mem.Disp)), nil
			}
		}
	}
	if called {
		return 0, 0, errors.New("could not follow the result of the TLS call")
	}
	return 0, 0, errors.New("could not find a GOT-based TLS access")
}

// writesFirstOperand reports whether op may write its first operand.
func writesFirstOperand(op x86asm.Op) bool {
	switch op {
	case x86asm.CMP, x86asm.TEST, x86asm.BT, x86asm.PUSH, x86asm.CALL, x86asm.JMP:
		return false
	}
	return true
}

// validateTLSOffset ensures that the extracted offset is within some boundaries.
func validateTLSOffset(offset int32) (int32, error) {
	// In theory all 32 bits can be used to represent the offset.
	// But usually this is not the case.
	// For more see https://www.akkadia.org/drepper/tls.pdf
	if (offset < 0 && offset > -4096) || (offset > 0 && offset < 4096) {
		return offset, nil
	}
	return 0, fmt.Errorf("could not find valid FS-relative MOV instruction")
}
