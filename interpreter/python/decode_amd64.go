// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/arch/x86/x86asm"
)

func decodeStubArgumentAMD64(code []byte, codeAddress, memoryBase uint64) uint64 {
	targetRegister := x86asm.RDI

	instructionOffset := 0
	regs := amd.RegsState{}

	for instructionOffset < len(code) {
		rem := code[instructionOffset:]
		if len(rem) >= 4 &&
			code[instructionOffset] == 0xf3 &&
			code[instructionOffset+1] == 0x0f &&
			code[instructionOffset+2] == 0x1e &&
			code[instructionOffset+3] == 0xfa {
			instructionOffset += 4
			continue
		}

		inst, err := x86asm.Decode(rem, 64)
		if err != nil { // todo return the error
			break
		}

		instructionOffset += inst.Len
		regs.Set(x86asm.RIP, codeAddress+uint64(instructionOffset), 0)

		if inst.Op == x86asm.CALL || inst.Op == x86asm.JMP {
			value, loadedFrom := regs.Get(targetRegister)
			if loadedFrom != 0 {
				return loadedFrom
			}
			return value
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
					} else if inst.Op == x86asm.LEA {
						value = baseAddr + displacement
					}

					if src.Index != 0 { // todo this is dead code according to test coverage, need a test or remove this
						indexValue, _ := regs.Get(src.Index)
						value += indexValue * uint64(src.Scale)
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
	return 0
}

func decodeStubArgumentWrapper(
	code []byte,
	codeAddress libpf.SymbolValue,
	memoryBase libpf.SymbolValue,
) libpf.SymbolValue {
	if len(code) == 0 {
		return 0
	}
	return libpf.SymbolValue(
		decodeStubArgumentAMD64(code, uint64(codeAddress), uint64(memoryBase)),
	)
}
