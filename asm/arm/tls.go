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

			// Check for MRS Xn, TPIDR_EL0 (system register S3_3_C13_C0_2)
			if inst.Op == aa.MRS && inst.Args[1].String() == "S3_3_C13_C0_2" {
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
	return 0, fmt.Errorf("found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset")
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
	capture := expression.NewImmediateCapture("slot")
	it := NewInterpreterWithCodeAt(code, expression.Imm(baseAddr))
	tpReg := -1
	called := false
	// The call returns the variable's address instead of its TP offset
	viaGetAddr := false
	offReg := -1

	for {
		// Registers before Step overwrites the destination
		regs := it.Regs
		inst, err := it.Step()
		if err != nil {
			break
		}
		off := offReg
		if called && writesFirstOperand(inst.Op) {
			if dst, ok := Xreg2num(inst.Args[0]); ok && dst == offReg {
				offReg = -1
			}
		}
		switch inst.Op {
		case aa.MRS:
			// arm64asm has no name for TPIDR_EL0
			if inst.Args[1].String() == "S3_3_C13_C0_2" {
				if reg, ok := Xreg2num(inst.Args[0]); ok {
					tpReg = reg
				}
			}
		case aa.BL:
			if called {
				return 0, 0, errors.New("unexpected call after TLS slot lookup")
			}
			// Pattern 3: BL __tls_get_addr with the tls_index in X0
			if regs.Get(X0).Match(capture) {
				slot = capture.CapturedValue()
				called = true
				viaGetAddr = true
				offReg = 0
			}
		case aa.BLR:
			if called {
				return 0, 0, errors.New("unexpected call after TLS slot lookup")
			}
			// Pattern 2: BLR Xr with the descriptor in X0. The resolver only
			// clobbers X0 and X30, so tpReg survives the call.
			if regs.Get(X0).Match(capture) {
				slot = capture.CapturedValue()
				called = true
				offReg = 0
			}
		case aa.LDR:
			// LDR Xd, [Xn, #imm] through the __tls_get_addr result
			if mem, ok := inst.Args[1].(aa.MemImmediate); ok && viaGetAddr {
				base, baseOk := Xreg2num(mem.Base)
				if !baseOk || base != off {
					continue
				}
				imm, immOk := DecodeImmediate(mem)
				if mem.Mode != aa.AddrOffset || !immOk {
					return 0, 0, fmt.Errorf("unsupported access to TLS call result: %v", inst)
				}
				return slot, disp + imm, nil
			}
			// LDR Xd, [Xt, Xn]
			mem, ok := inst.Args[1].(aa.MemExtend)
			if !ok {
				continue
			}
			base, baseOk := Xreg2num(mem.Base)
			index, indexOk := Xreg2num(mem.Index)
			if !baseOk || !indexOk || base != tpReg {
				continue
			}
			if called && !viaGetAddr && index == off {
				return slot, disp, nil
			}
			if regs.GetArm(mem.Index).Match(expression.Mem8(capture)) {
				return capture.CapturedValue(), 0, nil
			}
		case aa.ADD:
			dst, dstOk := Xreg2num(inst.Args[0])
			left, leftOk := Xreg2num(inst.Args[1])
			if !dstOk || !leftOk {
				continue
			}
			right, rightOk := Xreg2num(inst.Args[2])
			if !rightOk {
				// ADD X0, X0, #imm after the descriptor call
				if called && left == off {
					imm, ok := addImmediate(inst.Args[2])
					if !ok {
						return 0, 0, fmt.Errorf("unsupported ADD on TLS offset: %v", inst)
					}
					disp += imm
					offReg = dst
				}
				continue
			}
			// ADD Xd, Xt, Xn
			if called && !viaGetAddr &&
				(left == tpReg && right == off || left == off && right == tpReg) {
				return slot, disp, nil
			}
			if left == tpReg && regs.Get(X0+Reg(right)).Match(expression.Mem8(capture)) {
				return capture.CapturedValue(), 0, nil
			}
		}
	}
	if viaGetAddr {
		return 0, 0, errors.New("could not follow the address returned by the TLS call")
	}
	if called {
		return 0, 0, errors.New("could not follow the offset returned by the TLS descriptor call")
	}
	return 0, 0, errors.New("could not find a GOT-based TLS access")
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

// addImmediate is like DecodeImmediate, but applies LSL #12.
func addImmediate(arg aa.Arg) (int64, bool) {
	switch val := arg.(type) {
	case aa.Imm:
		return int64(val.Imm), true
	case aa.ImmShift:
		var imm, shift int64
		if n, _ := fmt.Sscanf(val.String(), "#%v, LSL #%d", &imm, &shift); n == 2 {
			return imm << shift, true
		}
		if n, _ := fmt.Sscanf(val.String(), "#%v", &imm); n == 1 {
			return imm, true
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
