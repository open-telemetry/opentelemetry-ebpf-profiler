// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"fmt"

	ah "go.opentelemetry.io/ebpf-profiler/armhelpers"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	aa "golang.org/x/arch/arm64/arm64asm"
)

// decodeStubArgumentARM64 disassembles arm64 code and decodes the assumed value
// of requested argument.
func decodeStubArgumentARM64(code []byte,
	addrBase libpf.SymbolValue) libpf.SymbolValue {
	const argNumber uint8 = 0
	// The concept is to track the latest load offset for all X0..X30 registers.
	// These registers are used as the function arguments. Once the first branch
	// instruction (function call/tail jump) is found, the state of the requested
	// argument register's offset is inspected and returned if found.
	// It is seen often that the load with offset happens to intermediate register
	// first, and is later moved to the argument register. Because of this, the
	// tracking requires extra effort between register moves etc.

	// PyEval_ReleaseLock (Amazon Linux /usr/lib64/libpython3.7m.so.1.0):
	// ADRP X0, .+0x148000
	// LDR X1, [X0,#1960]
	// ADD X2, X1, #0x5d8		1. X2's regOffset is 0x5d8 (the value we want)
	// LDR X0, [X2]			2. The argument register is loaded via X2
	// B .+0xfffffffffffffe88

	// PyGILState_GetThisThreadState (Amazon Linux /usr/lib64/libpython3.7m.so.1.0):
	// ADRP X0, .+0x251000
	// LDR X2, [X0,#1960]
	// LDR X1, [X2,#1512]
	// CBZ X1, .+0xc
	// ADD X0, X2, #0x5f0		1. X0's regOffset gets 0x5f0
	// B .+0xfffffffffffb92b4

	// PyGILState_GetThisThreadState (Debian 11 /usr/bin/python3):
	// ADRP X0, #0x907000
	// ADD  X2, X0, #0x880
	// ADD  X3, X2, #0x10
	// LDR  X1, [X2,#0x260]
	// CBZ  X1, loc_4740BC
	// LDR  W0, [X3,#0x25C] ; key
	// B    .pthread_getspecific

	// Storage for load offsets for each Xn register
	var regOffset [32]int64
	retValue := libpf.SymbolValueInvalid

	for offs := 0; offs < len(code); offs += 4 {
		inst, err := aa.Decode(code[offs:])
		if err != nil {
			return libpf.SymbolValueInvalid
		}
		if inst.Op == aa.B {
			return retValue
		}

		// Interested only on commands modifying Xn
		dest, ok := ah.Xreg2num(inst.Args[0])
		if !ok {
			continue
		}

		instOffset := int64(0)
		instRetval := libpf.SymbolValueInvalid
		switch inst.Op {
		case aa.ADD:
			a2, ok := ah.DecodeImmediate(inst.Args[2])
			if !ok {
				break
			}
			instOffset = a2
			instRetval = addrBase + libpf.SymbolValue(a2)
		case aa.LDR:
			m, ok := inst.Args[1].(aa.MemImmediate)
			if !ok {
				break
			}
			src, ok := ah.Xreg2num(m.Base)
			if !ok {
				break
			}
			imm, ok := ah.DecodeImmediate(inst.Args[1])
			if !ok {
				break
			}
			// FIXME: addressing mode not taken into account
			// because m.imm is not public, but needed.
			instRetval = addrBase + libpf.SymbolValue(regOffset[src]+imm)
		}
		regOffset[dest] = instOffset
		if dest == int(argNumber) {
			retValue = instRetval
		}
	}

	return libpf.SymbolValueInvalid
}

// extractTLSOffsetFromCodeARM64 extracts the TLS offset by analyzing ARM64 assembly code.
// It looks for the pattern: MRS Xn, TPIDR_EL0 followed by ADD Xn, Xn, #offset or LDR [Xn, #offset].
func extractTLSOffsetFromCodeARM64(code []byte, baseAddr uint64, visited map[uint64]bool, depth int, ef *pfelf.File) (int64, error) {
	// Prevent infinite recursion
	const maxDepth = 5
	if depth > maxDepth {
		return 0, fmt.Errorf("max recursion depth exceeded")
	}

	if visited[baseAddr] {
		return 0, fmt.Errorf("already visited address 0x%x", baseAddr)
	}
	visited[baseAddr] = true

	foundMRS := false
	var tpReg int

	for offs := 0; offs < len(code)-4; offs += 4 {
		inst, err := aa.Decode(code[offs:])
		if err != nil {
			continue
		}

		// Check for MRS Xn, TPIDR_EL0 (system register S3_3_C13_C0_2)
		if inst.Op == aa.MRS && inst.Args[1].String() == "S3_3_C13_C0_2" {
			reg, ok := ah.Xreg2num(inst.Args[0])
			if !ok {
				continue
			}
			tpReg = reg
			foundMRS = true

			// Look ahead for ADD or LDR using this register
			for j := offs + 4; j < len(code)-4 && j < offs+64; j += 4 {
				nextInst, err := aa.Decode(code[j:])
				if err != nil {
					continue
				}

				// Check for ADD Xd, Xn, #imm
				if nextInst.Op == aa.ADD {
					destReg, destOk := ah.Xreg2num(nextInst.Args[0])
					srcReg, srcOk := ah.Xreg2num(nextInst.Args[1])
					imm, immOk := ah.DecodeImmediate(nextInst.Args[2])

					if destOk && srcOk && immOk && srcReg == tpReg {
						if imm > 0 && imm < 0x1000 {
							return int64(imm), nil
						}
						// Track the new register holding TP+offset
						tpReg = destReg
					}
				}

				// Check for LDR Xm, [Xn, #imm]
				if nextInst.Op == aa.LDR {
					// Args[1] is MemImmediate
					if mem, ok := nextInst.Args[1].(aa.MemImmediate); ok {
						baseReg, regOk := ah.Xreg2num(mem.Base)
						imm, immOk := ah.DecodeImmediate(mem)

						if regOk && immOk && baseReg == tpReg {
							if imm > 0 && imm < 0x1000 {
								return int64(imm), nil
							}
						}
					}
				}
			}
		}

		// Check for unconditional branch
		if inst.Op == aa.B {
			if pcrel, ok := inst.Args[0].(aa.PCRel); ok {
				targetAddr := int64(baseAddr) + int64(offs) + int64(pcrel)

				if targetAddr > 0 && targetAddr < 0x100000000 && !visited[uint64(targetAddr)] {
					targetCode := make([]byte, 256)
					err := ef.GetRemoteMemory().Read(libpf.Address(targetAddr), targetCode)
					if err == nil {
						if result, err := extractTLSOffsetFromCodeARM64(targetCode, uint64(targetAddr), visited, depth+1, ef); err == nil {
							return result, nil
						}
					}
				}
			}
		}
	}

	if !foundMRS {
		return 0, fmt.Errorf("could not find MRS TPIDR_EL0 instruction")
	}
	return 0, fmt.Errorf("found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset")
}
