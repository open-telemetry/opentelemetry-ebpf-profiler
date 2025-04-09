// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"errors"
	"fmt"
	"runtime"

	ah "go.opentelemetry.io/ebpf-profiler/armhelpers"
	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	aa "golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
)

// decodeStubArgumentWrapperARM64 disassembles arm64 code and decodes the assumed value
// of requested argument.
func decodeStubArgumentWrapperARM64(code []byte,
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
	var regOffset [32]uint64
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

		instOffset := uint64(0)
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

func decodeStubArgumentAMD64(code []byte, codeAddress, memoryBase uint64) (
	libpf.SymbolValue, error) {
	targetRegister := x86asm.RDI

	instructionOffset := 0
	regs := amd.RegsState{}

	for instructionOffset < len(code) {
		rem := code[instructionOffset:]
		if endbr64, insnLen := amd.IsEndbr64(rem); endbr64 {
			instructionOffset += insnLen
			continue
		}

		inst, err := x86asm.Decode(rem, 64)
		if err != nil {
			return 0, fmt.Errorf("failed to decode instruction at 0x%x : %w",
				instructionOffset, err)
		}
		instructionOffset += inst.Len
		regs.Set(x86asm.RIP, codeAddress+uint64(instructionOffset), 0)

		if inst.Op == x86asm.CALL || inst.Op == x86asm.JMP {
			value, loadedFrom := regs.Get(targetRegister)
			if loadedFrom != 0 {
				return libpf.SymbolValue(loadedFrom), nil
			}
			return libpf.SymbolValue(value), nil
		}

		if (inst.Op == x86asm.LEA || inst.Op == x86asm.MOV) && inst.Args[0] != nil {
			if reg, ok := inst.Args[0].(x86asm.Reg); ok {
				var value uint64
				var loadedFrom uint64

				switch src := inst.Args[1].(type) {
				case x86asm.Imm:
					value = uint64(src)
				case x86asm.Mem:
					baseAddr, _ := regs.Get(src.Base)
					displacement := uint64(src.Disp)

					if inst.Op == x86asm.MOV {
						value = memoryBase
						loadedFrom = baseAddr + displacement
						if src.Index != 0 {
							indexValue, _ := regs.Get(src.Index)
							loadedFrom += indexValue * uint64(src.Scale)
						}
					} else if inst.Op == x86asm.LEA {
						value = baseAddr + displacement
						if src.Index != 0 {
							indexValue, _ := regs.Get(src.Index)
							value += indexValue * uint64(src.Scale)
						}
					}

				case x86asm.Reg:
					value, _ = regs.Get(src)
				}

				regs.Set(reg, value, loadedFrom)
			}
		}

		if inst.Op == x86asm.ADD && inst.Args[0] != nil && inst.Args[1] != nil {
			if reg, ok0 := inst.Args[0].(x86asm.Reg); ok0 {
				if _, ok1 := inst.Args[1].(x86asm.Mem); ok1 {
					oldValue, _ := regs.Get(reg)
					value := oldValue + memoryBase
					regs.Set(reg, value, 0)
				}
			}
		}
	}
	return 0, errors.New("no call/jump instructions found")
}

func decodeStubArgumentWrapper(
	code []byte,
	codeAddress libpf.SymbolValue,
	memoryBase libpf.SymbolValue,
) (libpf.SymbolValue, error) {
	if runtime.GOARCH == "arm64" {
		return decodeStubArgumentWrapperARM64(code, memoryBase), nil
	}
	if runtime.GOARCH == "amd64" {
		return decodeStubArgumentAMD64(code, uint64(codeAddress), uint64(memoryBase))
	}
	return libpf.SymbolValueInvalid, fmt.Errorf("unsupported arch %s", runtime.GOARCH)
}
