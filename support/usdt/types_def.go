// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package usdt // import "go.opentelemetry.io/ebpf-profiler/support/usdt"

/*
#include "../ebpf/usdt.h"
*/
import "C"

// ArgType represents the type of USDT argument (libbpf-compatible)
type ArgType = uint32

// Argument type constants
const (
	ArgConst    = C.BPF_USDT_ARG_CONST
	ArgReg      = C.BPF_USDT_ARG_REG
	ArgRegDeref = C.BPF_USDT_ARG_REG_DEREF
)

// Register represents CPU registers that can be used in USDT args
type Register = uint8

// Register ID constants - x86_64 and ARM64
const (
	RegNone = C.BPF_USDT_REG_NONE

	// x86_64 registers (1-17)
	RegRax = C.BPF_USDT_REG_RAX
	RegRbx = C.BPF_USDT_REG_RBX
	RegRcx = C.BPF_USDT_REG_RCX
	RegRdx = C.BPF_USDT_REG_RDX
	RegRsi = C.BPF_USDT_REG_RSI
	RegRdi = C.BPF_USDT_REG_RDI
	RegRbp = C.BPF_USDT_REG_RBP
	RegRsp = C.BPF_USDT_REG_RSP
	RegR8  = C.BPF_USDT_REG_R8
	RegR9  = C.BPF_USDT_REG_R9
	RegR10 = C.BPF_USDT_REG_R10
	RegR11 = C.BPF_USDT_REG_R11
	RegR12 = C.BPF_USDT_REG_R12
	RegR13 = C.BPF_USDT_REG_R13
	RegR14 = C.BPF_USDT_REG_R14
	RegR15 = C.BPF_USDT_REG_R15
	RegRip = C.BPF_USDT_REG_RIP

	// ARM64 registers (32-64)
	RegX0  = C.BPF_USDT_REG_X0
	RegX1  = C.BPF_USDT_REG_X1
	RegX2  = C.BPF_USDT_REG_X2
	RegX3  = C.BPF_USDT_REG_X3
	RegX4  = C.BPF_USDT_REG_X4
	RegX5  = C.BPF_USDT_REG_X5
	RegX6  = C.BPF_USDT_REG_X6
	RegX7  = C.BPF_USDT_REG_X7
	RegX8  = C.BPF_USDT_REG_X8
	RegX9  = C.BPF_USDT_REG_X9
	RegX10 = C.BPF_USDT_REG_X10
	RegX11 = C.BPF_USDT_REG_X11
	RegX12 = C.BPF_USDT_REG_X12
	RegX13 = C.BPF_USDT_REG_X13
	RegX14 = C.BPF_USDT_REG_X14
	RegX15 = C.BPF_USDT_REG_X15
	RegX16 = C.BPF_USDT_REG_X16
	RegX17 = C.BPF_USDT_REG_X17
	RegX18 = C.BPF_USDT_REG_X18
	RegX19 = C.BPF_USDT_REG_X19
	RegX20 = C.BPF_USDT_REG_X20
	RegX21 = C.BPF_USDT_REG_X21
	RegX22 = C.BPF_USDT_REG_X22
	RegX23 = C.BPF_USDT_REG_X23
	RegX24 = C.BPF_USDT_REG_X24
	RegX25 = C.BPF_USDT_REG_X25
	RegX26 = C.BPF_USDT_REG_X26
	RegX27 = C.BPF_USDT_REG_X27
	RegX28 = C.BPF_USDT_REG_X28
	RegX29 = C.BPF_USDT_REG_X29
	RegX30 = C.BPF_USDT_REG_X30
	RegSP  = C.BPF_USDT_REG_SP
	RegPC  = C.BPF_USDT_REG_PC
)

// ArgSpec represents a single USDT argument specification
// Must match struct bpf_usdt_arg_spec in ../ebpf/usdt.h
type ArgSpec C.struct_bpf_usdt_arg_spec

// Spec represents all arguments for a USDT probe (libbpf-compatible)
// Must match struct bpf_usdt_spec in ../ebpf/usdt.h
type Spec C.struct_bpf_usdt_spec
