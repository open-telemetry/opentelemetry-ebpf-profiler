// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"fmt"
	"runtime"

	ah "go.opentelemetry.io/ebpf-profiler/armhelpers"
	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/variable"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	aa "golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"
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

func decodeStubArgumentAMD64(
	code []byte,
	codeAddress, memBase uint64,
) (
	libpf.SymbolValue, error,
) {
	it := amd.NewInterpreterWithCode(code)
	it.CodeAddress = variable.Imm(codeAddress)
	_, err := it.LoopWithBreak(func(op x86asm.Inst) bool {
		return op.Op == x86asm.JMP || op.Op == x86asm.CALL
	})
	if err != nil {
		return 0, err
	}
	answer, err := evaluateStubAnswerAMD64(it.Regs.Get(x86asm.RDI), memBase)
	if err != nil {
		return 0, err
	}
	return libpf.SymbolValue(answer), err
}

func evaluateStubAnswerAMD64(res variable.U64, memBase uint64) (uint64, error) {
	answer := variable.Var("answer")
	if res.Eval(variable.ZeroExtend(variable.Mem(answer, 8), 32)) {
		return answer.ExtractedValueImm(), nil
	}
	if res.Eval(
		variable.Add(
			variable.Mem(variable.Var("mem"), 8),
			answer,
		),
	) {
		return memBase + answer.ExtractedValueImm(), nil
	}
	if res.Eval(
		variable.ZeroExtend(
			variable.Mem(
				variable.Add(
					variable.Mem(variable.Var("mem"), 8),
					answer,
				),
				8,
			),
			32,
		),
	) {
		return memBase + answer.ExtractedValueImm(), nil
	}
	if res.Eval(answer) {
		return answer.ExtractedValueImm(), nil
	}
	return 0, fmt.Errorf("not found %s", res.String())
}

func decodeStubArgumentWrapper(
	code []byte,
	codeAddress libpf.SymbolValue,
	memoryBase libpf.SymbolValue,
) (libpf.SymbolValue, error) {
	switch runtime.GOARCH {
	case "arm64":
		return decodeStubArgumentARM64(code, memoryBase), nil
	case "amd64":
		return decodeStubArgumentAMD64(code, uint64(codeAddress), uint64(memoryBase))
	default:
		return libpf.SymbolValueInvalid, fmt.Errorf("unsupported arch %s", runtime.GOARCH)
	}
}
