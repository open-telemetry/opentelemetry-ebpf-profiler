// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	aa "golang.org/x/arch/arm64/arm64asm"
)

// decodeStubArgumentARM64 disassembles arm64 code and decodes the assumed value
// of requested argument. symAddr is the virtual address of the first instruction
// in code[], needed to resolve ADRP PC-relative addresses.
func decodeStubArgumentARM64(code []byte,
	addrBase libpf.SymbolValue, symAddr uint64) libpf.SymbolValue {
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

	// PyGILState_GetThisThreadState (Python 3.12, static):
	// BTI  C
	// ADRP X0, 60c000
	// ADD  X0, X0, #0x818      ; X0 = _PyRuntime (directly, no GOT indirection)
	// LDR  W1, [X0,#1544]      ; tss_is_created check
	// CBZ  W1, ...
	// LDR  W0, [X0,#1548]      ; load pthread key from _PyRuntime+0x60c
	// B    pthread_getspecific

	// Symbolic offset from addrBase for each Xn register.
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
		dest, ok := arm.Xreg2num(inst.Args[0])
		if !ok {
			continue
		}

		// ADRP computes a PC-relative page address: (PC & ~0xFFF) + signext(imm << 12).
		// Store it as an offset from addrBase so subsequent ADD/LDR naturally compose.
		if inst.Op == aa.ADRP {
			pcrel, ok := arm.DecodeImmediate(inst.Args[1])
			if ok {
				pc := symAddr + uint64(offs)
				pageAddr := (pc & ^uint64(0xFFF)) + uint64(pcrel)
				regOffset[dest] = int64(pageAddr) - int64(addrBase)
			}
			continue
		}

		instOffset := int64(0)
		instRetval := libpf.SymbolValueInvalid
		switch inst.Op {
		case aa.ADD:
			a2, ok := arm.DecodeImmediate(inst.Args[2])
			if !ok {
				break
			}
			src, ok := arm.Xreg2num(inst.Args[1])
			if !ok {
				break
			}
			// Accumulate src's offset: for GOT-indirect regOffset[src] is 0
			// so this is just a2; for ADRP+ADD it includes the page offset.
			instOffset = regOffset[src] + a2
			instRetval = addrBase + libpf.SymbolValue(instOffset)
		case aa.LDR:
			m, ok := inst.Args[1].(aa.MemImmediate)
			if !ok {
				break
			}
			src, ok := arm.Xreg2num(m.Base)
			if !ok {
				break
			}
			imm, ok := arm.DecodeImmediate(inst.Args[1])
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
