// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm // import "go.opentelemetry.io/ebpf-profiler/asm/arm"

import (
	"errors"
	"fmt"

	aa "golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// tpidrEL0 is how arm64asm renders the thread pointer system register, which
// it has no name for.
const tpidrEL0 = "S3_3_C13_C0_2"

// branchTarget represents a branch target to be analyzed
type branchTarget struct {
	addr  uint64
	depth int
}

// ExtractTLSOffset extracts the TLS offset by analyzing ARM64 assembly code.
// It looks for the pattern: MRS Xn, TPIDR_EL0 followed by ADD Xn, Xn, #offset or LDR [Xn, #offset].
func ExtractTLSOffset(code []byte, baseAddr uint64, ef *pfelf.File) (int32, error) {
	const maxDepth = 5
	const maxIterations = 100

	// Work queue for branches to follow
	queue := []branchTarget{{addr: baseAddr, depth: 0}}
	visited := make(map[uint64]bool)

	iterations := 0
	foundMRS := false

	for len(queue) > 0 && iterations < maxIterations {
		iterations++

		// Pop from queue
		current := queue[0]
		queue = queue[1:]

		// Check if already visited or depth exceeded
		if visited[current.addr] || current.depth > maxDepth {
			continue
		}
		visited[current.addr] = true

		var codeToAnalyze []byte
		var codeBaseAddr uint64

		if current.addr == baseAddr {
			codeToAnalyze = code
			codeBaseAddr = baseAddr
		} else {
			targetCode := make([]byte, 256)
			err := ef.GetRemoteMemory().Read(libpf.Address(current.addr), targetCode)
			if err != nil {
				continue
			}
			codeToAnalyze = targetCode
			codeBaseAddr = current.addr
		}

		var tpReg int

		for offs := 0; offs < len(codeToAnalyze)-4; offs += 4 {
			inst, err := aa.Decode(codeToAnalyze[offs:])
			if err != nil {
				continue
			}

			// Check for MRS Xn, TPIDR_EL0
			if inst.Op == aa.MRS && inst.Args[1].String() == tpidrEL0 {
				reg, ok := Xreg2num(inst.Args[0])
				if !ok {
					continue
				}
				tpReg = reg
				foundMRS = true

				// Look ahead for ADD or LDR using this register
				for j := offs + 4; j < len(codeToAnalyze)-4 && j < offs+64; j += 4 {
					nextInst, err := aa.Decode(codeToAnalyze[j:])
					if err != nil {
						continue
					}

					// Check for ADD Xd, Xn, #imm
					if nextInst.Op == aa.ADD {
						destReg, destOk := Xreg2num(nextInst.Args[0])
						srcReg, srcOk := Xreg2num(nextInst.Args[1])
						imm, immOk := DecodeImmediate(nextInst.Args[2])

						if destOk && srcOk && immOk && srcReg == tpReg {
							if imm > 0 && imm < 0x1000 {
								return validateTLSOffset(int32(imm))
							}
							// Track the new register holding TP+offset
							tpReg = destReg
						}
					}

					// Check for LDR Xm, [Xn, #imm]
					if nextInst.Op == aa.LDR {
						// Args[1] is MemImmediate
						if mem, ok := nextInst.Args[1].(aa.MemImmediate); ok {
							baseReg, regOk := Xreg2num(mem.Base)
							imm, immOk := DecodeImmediate(mem)

							if regOk && immOk && baseReg == tpReg {
								if imm > 0 && imm < 0x1000 {
									return validateTLSOffset(int32(imm))
								}
							}
						}
					}
				}
			}

			// Check for unconditional branch and add to queue
			if inst.Op == aa.B {
				if pcrel, ok := inst.Args[0].(aa.PCRel); ok {
					targetAddr := int64(codeBaseAddr) + int64(offs) + int64(pcrel)

					if targetAddr > 0 && targetAddr < 0x100000000 && !visited[uint64(targetAddr)] {
						queue = append(queue, branchTarget{
							addr:  uint64(targetAddr),
							depth: current.depth + 1,
						})
					}
				}
			}
		}

		// If we found MRS in this block but no valid offset, continue to next block
		if foundMRS {
			// We found MRS but didn't return, meaning no valid offset was found in this block
			// Continue with other blocks in the queue
			continue
		}
	}

	if !foundMRS {
		return 0, fmt.Errorf("could not find MRS TPIDR_EL0 instruction")
	}
	// The scan above only follows an offset that an ADD or LDR encodes as an
	// immediate. Where the offset sits in a register instead, recovering it
	// takes the interpreter.
	if offset, err := extractRelaxedTLSOffset(code, baseAddr); err == nil {
		return offset, nil
	}
	return 0, fmt.Errorf("found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset")
}

// extractRelaxedTLSOffset decodes a local-exec access that indexes the thread
// pointer with a register. The linker leaves this behind when it relaxes a
// general-dynamic access, replacing the call to __tls_get_addr with a MOVZ and
// MOVK pair that materializes the TP-relative offset.
func extractRelaxedTLSOffset(code []byte, baseAddr uint64) (int32, error) {
	capture := expression.NewImmediateCapture("offset")
	it := NewInterpreterWithCodeAt(code, expression.Imm(baseAddr))
	tpReg := noReg

	for {
		// A load can read through the register it writes, so the index is
		// taken from the state from before the step.
		regs := it.Regs
		inst, err := it.Step()
		if err != nil {
			break
		}
		switch inst.Op {
		case aa.MRS:
			if inst.Args[1].String() != tpidrEL0 {
				continue
			}
			if reg, ok := Xreg2num(inst.Args[0]); ok {
				tpReg = reg
			}
		case aa.LDR:
			// A scaled index would multiply the offset, so only the plain
			// form carries it unchanged.
			mem, ok := inst.Args[1].(aa.MemExtend)
			if !ok || mem.Amount != 0 {
				continue
			}
			if base, ok := Xreg2num(mem.Base); !ok || base != tpReg {
				continue
			}
			if regs.GetArm(mem.Index).Match(capture) {
				return validateTLSOffset(int32(capture.CapturedValue()))
			}
		}
	}
	return 0, errors.New("no TP-relative offset held in a register")
}

// noReg marks a tlsSlotScan register field that currently tracks nothing.
const noReg = -1

// tlsSlotScan holds the state that ExtractTLSSlot carries from one instruction
// to the next while it walks a TLS access sequence.
type tlsSlotScan struct {
	// capture matches the slot address wherever the code materializes it
	capture *expression.ImmediateCapture
	// slot is the slot address seen at the call site
	slot uint64
	// disp sums the immediates added to the call result
	disp int64
	// tpReg is the register an MRS read the thread pointer into
	tpReg int
	// resReg is the register still holding the call result
	resReg int
	// called records that the descriptor resolver or __tls_get_addr ran
	called bool
	// viaGetAddr means the call returned the variable's address instead of
	// its offset from the thread pointer
	viaGetAddr bool
}

// ExtractTLSSlot finds the GOT slot or TLS descriptor that ARM64 code in a
// shared library uses to reach a TLS variable. Supported sequences:
//  1. Initial-exec: ADRP/LDR of the GOT slot, MRS TPIDR_EL0, then LDR or ADD
//     with both registers
//  2. TLS descriptor: ADRP/LDR/ADD X0 and BLR, with optional ADDs to X0 after
//  3. General/local-dynamic: ADRP/ADD X0, BL __tls_get_addr, then LDR through
//     X0, with optional ADDs to X0 in between
//
// Besides the slot address, it returns the sum of immediates added to the
// call result.
func ExtractTLSSlot(code []byte, baseAddr uint64) (slot uint64, disp int64, err error) {
	s := tlsSlotScan{
		capture: expression.NewImmediateCapture("slot"),
		tpReg:   noReg,
		resReg:  noReg,
	}
	it := NewInterpreterWithCodeAt(code, expression.Imm(baseAddr))

	for {
		// Registers before Step overwrites the destination
		regs := it.Regs
		inst, stepErr := it.Step()
		if stepErr != nil {
			break
		}
		res := s.takeResultReg(inst)

		var done bool
		var matchErr error
		switch inst.Op {
		case aa.MRS:
			s.matchThreadPointer(inst)
		case aa.BL:
			// Pattern 3 hands the tls_index to __tls_get_addr in X0
			matchErr = s.matchCall(&regs, true)
		case aa.BLR:
			// Pattern 2 hands the descriptor to the resolver in X0
			matchErr = s.matchCall(&regs, false)
		case aa.LDR:
			done, matchErr = s.matchLoad(&regs, inst, res)
		case aa.ADD:
			done, matchErr = s.matchAdd(&regs, inst, res)
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
// inst, and stops tracking it if inst overwrites it.
func (s *tlsSlotScan) takeResultReg(inst aa.Inst) int {
	prev := s.resReg
	if s.called && writesFirstOperand(inst.Op) {
		if dst, ok := Xreg2num(inst.Args[0]); ok && dst == s.resReg {
			s.resReg = noReg
		}
	}
	return prev
}

// matchThreadPointer notes the register an MRS reads the thread pointer into.
func (s *tlsSlotScan) matchThreadPointer(inst aa.Inst) {
	if inst.Args[1].String() != tpidrEL0 {
		return
	}
	if reg, ok := Xreg2num(inst.Args[0]); ok {
		s.tpReg = reg
	}
}

// matchCall captures the slot address that a call to __tls_get_addr or to a
// TLS descriptor resolver takes in X0. Both clobber only X0 and X30, so the
// thread pointer register survives the call.
func (s *tlsSlotScan) matchCall(regs *Registers, viaGetAddr bool) error {
	if s.called {
		return errors.New("unexpected call after TLS slot lookup")
	}
	if !regs.Get(X0).Match(s.capture) {
		return nil
	}
	s.slot = s.capture.CapturedValue()
	s.called = true
	s.viaGetAddr = viaGetAddr
	s.resReg = 0
	return nil
}

// matchLoad follows an LDR that dereferences either the address __tls_get_addr
// returned, or the thread pointer indexed by a TP-relative offset.
func (s *tlsSlotScan) matchLoad(regs *Registers, inst aa.Inst, res int) (bool, error) {
	// LDR Xd, [Xn, #imm] through the __tls_get_addr result
	if mem, ok := inst.Args[1].(aa.MemImmediate); ok && s.viaGetAddr {
		base, baseOk := Xreg2num(mem.Base)
		if !baseOk || base != res {
			return false, nil
		}
		imm, immOk := DecodeImmediate(mem)
		if mem.Mode != aa.AddrOffset || !immOk {
			return false, fmt.Errorf("unsupported access to TLS call result: %v", inst)
		}
		s.disp += imm
		return true, nil
	}
	// LDR Xd, [Xt, Xn]
	mem, ok := inst.Args[1].(aa.MemExtend)
	if !ok {
		return false, nil
	}
	base, baseOk := Xreg2num(mem.Base)
	index, indexOk := Xreg2num(mem.Index)
	if !baseOk || !indexOk || base != s.tpReg {
		return false, nil
	}
	// The descriptor call left the offset in the index register
	if s.called && !s.viaGetAddr && index == res {
		return true, nil
	}
	// Initial-exec takes the offset straight out of the GOT slot
	if regs.GetArm(mem.Index).Match(expression.Mem8(s.capture)) {
		s.slot = s.capture.CapturedValue()
		s.disp = 0
		return true, nil
	}
	return false, nil
}

// matchAdd folds an immediate into the displacement, or ends the sequence
// where a TP-relative offset is added to the thread pointer.
func (s *tlsSlotScan) matchAdd(regs *Registers, inst aa.Inst, res int) (bool, error) {
	dst, dstOk := Xreg2num(inst.Args[0])
	left, leftOk := Xreg2num(inst.Args[1])
	if !dstOk || !leftOk {
		return false, nil
	}
	right, rightOk := Xreg2num(inst.Args[2])
	if !rightOk {
		// ADD X0, X0, #imm after the descriptor call
		if s.called && left == res {
			imm, ok := addImmediate(inst.Args[2])
			if !ok {
				return false, fmt.Errorf("unsupported ADD on TLS offset: %v", inst)
			}
			s.disp += imm
			s.resReg = dst
		}
		return false, nil
	}
	// ADD Xd, Xt, Xn with the offset the descriptor call returned
	if s.called && !s.viaGetAddr &&
		(left == s.tpReg && right == res || left == res && right == s.tpReg) {
		return true, nil
	}
	// Initial-exec takes the offset straight out of the GOT slot
	if left == s.tpReg && regs.Get(X0+Reg(right)).Match(expression.Mem8(s.capture)) {
		s.slot = s.capture.CapturedValue()
		s.disp = 0
		return true, nil
	}
	return false, nil
}

// unresolved names the stage of the sequence the scan did not get past.
func (s *tlsSlotScan) unresolved() error {
	switch {
	case s.viaGetAddr:
		return errors.New("could not follow the address returned by the TLS call")
	case s.called:
		return errors.New("could not follow the offset returned by the TLS descriptor call")
	default:
		return errors.New("could not find a GOT-based TLS access")
	}
}

// writesFirstOperand is false for stores, compares and branches.
func writesFirstOperand(op aa.Op) bool {
	switch op {
	case aa.STR, aa.STRB, aa.STRH, aa.STUR, aa.STURB, aa.STURH, aa.STP,
		aa.CMP, aa.CMN, aa.TST, aa.CBZ, aa.CBNZ, aa.TBZ, aa.TBNZ,
		aa.B, aa.BL, aa.BLR, aa.BR, aa.RET:
		return false
	}
	return true
}

// addImmediate is like DecodeImmediate, but applies the shift an ADD encodes
// along with its immediate.
func addImmediate(arg aa.Arg) (int64, bool) {
	switch val := arg.(type) {
	case aa.Imm:
		return int64(val.Imm), true
	case aa.ImmShift:
		if imm, shift, ok := immShift(val); ok {
			return int64(imm << shift), true
		}
	}
	return 0, false
}

// validateTLSOffset ensures that the extracted offset is within some boundaries.
func validateTLSOffset(offset int32) (int32, error) {
	// In theory all 32 bits can be used to represent the offset.
	// But usually this is not the case.
	// For more see https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
	if (offset < 0 && offset > -4096) || (offset > 0 && offset < 4096) {
		return offset, nil
	}
	return 0, fmt.Errorf("could not find valid FS-relative MOV instruction")
}
