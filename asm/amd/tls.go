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
// It handles four common patterns:
//  1. Direct FS-relative addressing: MOV reg, FS:[offset]
//  2. Register-based addressing: MOV $offset, reg; MOV reg, FS:(reg)
//  3. RIP-relative addressing: MOV 0x...(RIP), reg; MOV reg, FS:(reg)
//  4. Thread pointer in a register: MOV reg, FS:[0]; MOV reg, [reg+offset]
//
// The function returns the TLS offset found, or an error if no valid pattern is detected.
// For RIP-relative addressing, the file parameter can be provided to resolve memory references.
// If file is nil, RIP-relative memory dereferencing will be skipped.
func ExtractTLSOffset(code []byte, codeAddress uint64, file *pfelf.File) (int32, error) {
	offset := e.NewImmediateCapture("offset")
	it := NewInterpreterWithCodeAt(code, e.Imm(codeAddress))

	for {
		regs := it.Regs
		op, err := it.Step()
		if err != nil {
			break
		}
		if op.Op != x86asm.MOV {
			continue
		}
		mem, ok := op.Args[1].(x86asm.Mem)
		if !ok {
			continue
		}
		if mem.Segment != x86asm.FS {
			// Pattern 4: A load through a register holding the thread pointer,
			// which the linker leaves behind when it relaxes a general-dynamic
			// access to local-exec. The FS prefix stays on the thread pointer
			// read alone, so the offset has to come from the load address.
			if mem.Base == 0 || mem.Index != 0 {
				continue
			}
			at := e.Add(regs.GetX86(mem.Base), immFromDisp(mem.Disp))
			if at.Match(e.Add(threadPointer(), offset)) {
				return validateTLSOffset(int32(offset.CapturedValue()))
			}
			continue
		}
		// Pattern 1: Direct FS-relative addressing
		// Example: MOV rax, FS:[0xfffffffffffffff8]
		if mem.Base == 0 {
			if mem.Disp == 0 && mem.Index == 0 {
				// FS:[0] is the thread pointer itself and not a variable. The
				// access through the register it lands in carries the offset.
				continue
			}
			return validateTLSOffset(int32(mem.Disp))
		}
		// Pattern 2 & 3: Register-based or RIP-relative addressing
		// Example: MOV $0xfffffffffffffff8, rcx; MOV rax, FS:(rcx)
		// or: MOV 0x40b9af9(RIP), rcx; MOV rax, FS:(rcx)
		// The interpreter handles RIP-relative addressing transparently,
		// resolving it to a virtual memory address.
		actual := regs.GetX86(mem.Base)
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

// threadPointer is a read of FS:[0], which holds a copy of the thread pointer
// so that code can obtain it without a segment-relative access of its own.
func threadPointer() e.Expression {
	return e.MemWithSegment8(x86asm.FS, e.Imm(0))
}

// tlsSlotScan holds the state that ExtractTLSSlot carries from one instruction
// to the next while it walks a TLS access sequence.
type tlsSlotScan struct {
	// capture matches the slot address wherever the code materializes it
	capture *e.ImmediateCapture
	// slot is the slot address seen at the call site
	slot uint64
	// disp sums the immediates added to the call result
	disp int64
	// resReg is the register still holding the call result, or 0 for none
	resReg Reg
	// called records that the descriptor resolver or __tls_get_addr ran
	called bool
	// viaDescriptor means the call returned the variable's offset from the
	// thread pointer instead of its address
	viaDescriptor bool
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
	s := tlsSlotScan{capture: e.NewImmediateCapture("slot")}
	it := NewInterpreterWithCodeAt(code, e.Imm(codeAddress))

	for {
		// Registers before Step overwrites the destination
		regs := it.Regs
		op, stepErr := it.Step()
		if stepErr != nil {
			break
		}
		res := s.takeResultReg(op)

		var done bool
		var matchErr error
		switch op.Op {
		case x86asm.CALL:
			matchErr = s.matchCall(&regs, op)
		case x86asm.LEA:
			s.matchLea(op, res)
		case x86asm.ADD, x86asm.SUB:
			s.matchAddSub(op, res)
		case x86asm.MOV:
			done, matchErr = s.matchLoad(&regs, op, res)
		}
		if matchErr != nil {
			return 0, 0, matchErr
		}
		if done {
			return s.slot, s.disp, nil
		}
	}
	return 0, 0, s.unresolved()
}

// takeResultReg returns the register holding the call result as it was before
// op, and stops tracking it if op overwrites it.
func (s *tlsSlotScan) takeResultReg(op x86asm.Inst) Reg {
	prev := s.resReg
	if s.called && writesFirstOperand(op.Op) {
		if dst, ok := op.Args[0].(x86asm.Reg); ok && regMappingFor(dst).idx == s.resReg {
			s.resReg = 0
		}
	}
	return prev
}

// matchCall captures the slot address that a call to __tls_get_addr or to a
// TLS descriptor resolver takes in a register.
func (s *tlsSlotScan) matchCall(regs *Registers, op x86asm.Inst) error {
	if s.called {
		return errors.New("unexpected call after TLS slot lookup")
	}
	// __tls_get_addr takes its argument in RDI, also with -fno-plt.
	// Example: CALL [RAX] for a TLS descriptor
	argReg := x86asm.RDI
	if mem, ok := op.Args[0].(x86asm.Mem); ok &&
		mem.Base != 0 && mem.Base != x86asm.RIP {
		argReg = mem.Base
	}
	if !regs.GetX86(argReg).Match(s.capture) {
		return nil
	}
	s.slot = s.capture.CapturedValue()
	s.called = true
	s.viaDescriptor = argReg != x86asm.RDI
	s.resReg = RAX
	return nil
}

// matchLea folds the immediate of a LEA off the call result into the
// displacement and follows the result into its new register.
func (s *tlsSlotScan) matchLea(op x86asm.Inst, res Reg) {
	// LEA reg, [res+imm]
	dst, dstOk := op.Args[0].(x86asm.Reg)
	mem, memOk := op.Args[1].(x86asm.Mem)
	if !s.called || res == 0 || !dstOk || !memOk {
		return
	}
	if mem.Segment != 0 || mem.Index != 0 || mem.Base == 0 ||
		regMappingFor(mem.Base).idx != res {
		return
	}
	s.disp += int64(int32(mem.Disp))
	s.resReg = regMappingFor(dst).idx
}

// matchAddSub folds an immediate added to or subtracted from the call result
// into the displacement.
func (s *tlsSlotScan) matchAddSub(op x86asm.Inst, res Reg) {
	// ADD res, imm or SUB res, imm
	dst, dstOk := op.Args[0].(x86asm.Reg)
	imm, immOk := op.Args[1].(x86asm.Imm)
	if !s.called || res == 0 || !dstOk || !immOk || regMappingFor(dst).idx != res {
		return
	}
	if op.Op == x86asm.SUB {
		s.disp -= int64(imm)
	} else {
		s.disp += int64(imm)
	}
	s.resReg = res
}

// matchLoad follows a MOV that dereferences either the call result, or the
// thread pointer with an offset taken from the GOT slot.
func (s *tlsSlotScan) matchLoad(regs *Registers, op x86asm.Inst, res Reg) (bool, error) {
	mem, ok := op.Args[1].(x86asm.Mem)
	if !ok || mem.Base == 0 {
		return false, nil
	}
	// Pattern 2 & 3: access through the call result
	// Example: MOV rax, [rax+0x8]
	if s.called && res != 0 && regMappingFor(mem.Base).idx == res {
		if mem.Index != 0 || (mem.Segment == x86asm.FS) != s.viaDescriptor {
			return false, fmt.Errorf("unexpected access to TLS call result: %v", op)
		}
		s.disp += int64(int32(mem.Disp))
		return true, nil
	}
	// Pattern 1: FS-relative access with the offset from the GOT
	// Example: MOV 0x2ecd(RIP), rax; MOV rax, FS:(rax)
	if !s.called && mem.Segment == x86asm.FS &&
		regs.GetX86(mem.Base).Match(e.Mem8(s.capture)) {
		s.slot = s.capture.CapturedValue()
		s.disp = int64(int32(mem.Disp))
		return true, nil
	}
	return false, nil
}

// unresolved names the stage of the sequence the scan did not get past.
func (s *tlsSlotScan) unresolved() error {
	if s.called {
		return errors.New("could not follow the result of the TLS call")
	}
	return errors.New("could not find a GOT-based TLS access")
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
