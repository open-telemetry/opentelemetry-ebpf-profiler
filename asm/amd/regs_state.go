// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import "golang.org/x/arch/x86/x86asm"

// regIndex returns index into RegsState.regs
func regIndex(reg x86asm.Reg) int {
	switch reg {
	case x86asm.RAX, x86asm.EAX:
		return 1
	case x86asm.RBX, x86asm.EBX:
		return 2
	case x86asm.RCX, x86asm.ECX:
		return 3
	case x86asm.RDX, x86asm.EDX:
		return 4
	case x86asm.RDI, x86asm.EDI:
		return 5
	case x86asm.RSI, x86asm.ESI:
		return 6
	case x86asm.RBP, x86asm.EBP:
		return 7
	case x86asm.R8, x86asm.R8L:
		return 8
	case x86asm.R9, x86asm.R9L:
		return 9
	case x86asm.R10, x86asm.R10L:
		return 10
	case x86asm.R11, x86asm.R11L:
		return 11
	case x86asm.R12, x86asm.R12L:
		return 12
	case x86asm.R13, x86asm.R13L:
		return 13
	case x86asm.R14, x86asm.R14L:
		return 14
	case x86asm.R15, x86asm.R15L:
		return 15
	case x86asm.RSP, x86asm.ESP:
		return 16
	case x86asm.RIP:
		return 17
	default:
		return 0
	}
}

type RegsState struct {
	regs [18]regState
}

func (r *RegsState) Set(reg x86asm.Reg, value, loadedFrom uint64) {
	r.regs[regIndex(reg)].Value = value
	r.regs[regIndex(reg)].LoadedFrom = loadedFrom
}

func (r *RegsState) Get(reg x86asm.Reg) (value, loadedFrom uint64) {
	return r.regs[regIndex(reg)].Value, r.regs[regIndex(reg)].LoadedFrom
}

type regState struct {
	LoadedFrom uint64
	Value      uint64
}
