// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm // import "go.opentelemetry.io/ebpf-profiler/asm/arm"

import (
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/asm/expression"
)

type Registers struct {
	regs [int(registersCount)]expression.Expression
}

type regEntry struct {
	idx  Reg
	bits int
}
type Reg uint8

const (
	_ Reg = iota
	X0
	X1
	X2
	X3
	X4
	X5
	X6
	X7
	X8
	X9
	X10
	X11
	X12
	X13
	X14
	X15
	X16
	X17
	X18
	X19
	X20
	X21
	X22
	X23
	X24
	X25
	X26
	X27
	X28
	X29
	X30
	SP
	XZR
	PC
	registersCount
)

var regNames = [...]string{
	X0:  "X0",
	X1:  "X1",
	X2:  "X2",
	X3:  "X3",
	X4:  "X4",
	X5:  "X5",
	X6:  "X6",
	X7:  "X7",
	X8:  "X8",
	X9:  "X9",
	X10: "X10",
	X11: "X11",
	X12: "X12",
	X13: "X13",
	X14: "X14",
	X15: "X15",
	X16: "X16",
	X17: "X17",
	X18: "X18",
	X19: "X19",
	X20: "X20",
	X21: "X21",
	X22: "X22",
	X23: "X23",
	X24: "X24",
	X25: "X25",
	X26: "X26",
	X27: "X27",
	X28: "X28",
	X29: "X29",
	X30: "X30",
	SP:  "SP",
	XZR: "XZR",
	PC:  "PC",
}

func (r Reg) String() string {
	i := int(r)
	if r == 0 || i >= len(regNames) || regNames[i] == "" {
		return fmt.Sprintf("Reg(%d)", i)
	}
	return regNames[i]
}

func regMappingFor(reg arm64asm.Reg) regEntry {
	switch reg {
	case arm64asm.W0:
		return regEntry{idx: X0, bits: 32}
	case arm64asm.X0:
		return regEntry{idx: X0, bits: 64}
	case arm64asm.W1:
		return regEntry{idx: X1, bits: 32}
	case arm64asm.X1:
		return regEntry{idx: X1, bits: 64}
	case arm64asm.W2:
		return regEntry{idx: X2, bits: 32}
	case arm64asm.X2:
		return regEntry{idx: X2, bits: 64}
	case arm64asm.W3:
		return regEntry{idx: X3, bits: 32}
	case arm64asm.X3:
		return regEntry{idx: X3, bits: 64}
	case arm64asm.W4:
		return regEntry{idx: X4, bits: 32}
	case arm64asm.X4:
		return regEntry{idx: X4, bits: 64}
	case arm64asm.W5:
		return regEntry{idx: X5, bits: 32}
	case arm64asm.X5:
		return regEntry{idx: X5, bits: 64}
	case arm64asm.W6:
		return regEntry{idx: X6, bits: 32}
	case arm64asm.X6:
		return regEntry{idx: X6, bits: 64}
	case arm64asm.W7:
		return regEntry{idx: X7, bits: 32}
	case arm64asm.X7:
		return regEntry{idx: X7, bits: 64}
	case arm64asm.W8:
		return regEntry{idx: X8, bits: 32}
	case arm64asm.X8:
		return regEntry{idx: X8, bits: 64}
	case arm64asm.W9:
		return regEntry{idx: X9, bits: 32}
	case arm64asm.X9:
		return regEntry{idx: X9, bits: 64}
	case arm64asm.W10:
		return regEntry{idx: X10, bits: 32}
	case arm64asm.X10:
		return regEntry{idx: X10, bits: 64}
	case arm64asm.W11:
		return regEntry{idx: X11, bits: 32}
	case arm64asm.X11:
		return regEntry{idx: X11, bits: 64}
	case arm64asm.W12:
		return regEntry{idx: X12, bits: 32}
	case arm64asm.X12:
		return regEntry{idx: X12, bits: 64}
	case arm64asm.W13:
		return regEntry{idx: X13, bits: 32}
	case arm64asm.X13:
		return regEntry{idx: X13, bits: 64}
	case arm64asm.W14:
		return regEntry{idx: X14, bits: 32}
	case arm64asm.X14:
		return regEntry{idx: X14, bits: 64}
	case arm64asm.W15:
		return regEntry{idx: X15, bits: 32}
	case arm64asm.X15:
		return regEntry{idx: X15, bits: 64}
	case arm64asm.W16:
		return regEntry{idx: X16, bits: 32}
	case arm64asm.X16:
		return regEntry{idx: X16, bits: 64}
	case arm64asm.W17:
		return regEntry{idx: X17, bits: 32}
	case arm64asm.X17:
		return regEntry{idx: X17, bits: 64}
	case arm64asm.W18:
		return regEntry{idx: X18, bits: 32}
	case arm64asm.X18:
		return regEntry{idx: X18, bits: 64}
	case arm64asm.W19:
		return regEntry{idx: X19, bits: 32}
	case arm64asm.X19:
		return regEntry{idx: X19, bits: 64}
	case arm64asm.W20:
		return regEntry{idx: X20, bits: 32}
	case arm64asm.X20:
		return regEntry{idx: X20, bits: 64}
	case arm64asm.W21:
		return regEntry{idx: X21, bits: 32}
	case arm64asm.X21:
		return regEntry{idx: X21, bits: 64}
	case arm64asm.W22:
		return regEntry{idx: X22, bits: 32}
	case arm64asm.X22:
		return regEntry{idx: X22, bits: 64}
	case arm64asm.W23:
		return regEntry{idx: X23, bits: 32}
	case arm64asm.X23:
		return regEntry{idx: X23, bits: 64}
	case arm64asm.W24:
		return regEntry{idx: X24, bits: 32}
	case arm64asm.X24:
		return regEntry{idx: X24, bits: 64}
	case arm64asm.W25:
		return regEntry{idx: X25, bits: 32}
	case arm64asm.X25:
		return regEntry{idx: X25, bits: 64}
	case arm64asm.W26:
		return regEntry{idx: X26, bits: 32}
	case arm64asm.X26:
		return regEntry{idx: X26, bits: 64}
	case arm64asm.W27:
		return regEntry{idx: X27, bits: 32}
	case arm64asm.X27:
		return regEntry{idx: X27, bits: 64}
	case arm64asm.W28:
		return regEntry{idx: X28, bits: 32}
	case arm64asm.X28:
		return regEntry{idx: X28, bits: 64}
	case arm64asm.W29:
		return regEntry{idx: X29, bits: 32}
	case arm64asm.X29:
		return regEntry{idx: X29, bits: 64}
	case arm64asm.W30:
		return regEntry{idx: X30, bits: 32}
	case arm64asm.X30:
		return regEntry{idx: X30, bits: 64}
	// Note: WSP/SP are aliases for WZR/XZR in arm64asm.
	// If you need these to be interpreted as *SP, use regMappingForSp.
	case arm64asm.WZR:
		return regEntry{idx: XZR, bits: 32}
	case arm64asm.XZR:
		return regEntry{idx: XZR, bits: 64}
	default:
		return regEntry{idx: 0, bits: 64}
	}
}

func regMappingForSP(reg arm64asm.RegSP) regEntry {
	r := arm64asm.Reg(reg)
	switch r {
	case arm64asm.SP:
		return regEntry{idx: SP, bits: 64}
	case arm64asm.WSP:
		return regEntry{idx: SP, bits: 32}
	default:
		return regMappingFor(r)
	}
}

func (r *Registers) setArm64asm(reg arm64asm.Reg, v expression.Expression) {
	e := regMappingFor(reg)
	if e.idx == XZR {
		// stores to *ZR are ignored.
		return
	}
	if e.bits != 64 {
		v = expression.ZeroExtend(v, e.bits)
	}
	r.regs[e.idx] = v
}

func (r *Registers) setArm64asmSP(reg arm64asm.RegSP, v expression.Expression) {
	e := regMappingForSP(reg)
	if e.bits != 64 {
		v = expression.ZeroExtend(v, e.bits)
	}
	r.regs[e.idx] = v
}

// setPC sets the value of the PC register. PC is not a possible value of
// arm64asm.Reg, so this needs to be a separate function.
func (r *Registers) setPC(v expression.Expression) {
	r.regs[PC] = v
}

// GetArm returns the expression.Expression value associated with the given arm64asm.Reg, zero-extended
// to 64 bits if necessary.
func (r *Registers) GetArm(reg arm64asm.Reg) expression.Expression {
	e := regMappingFor(reg)
	if e.idx == XZR {
		// *ZR always reads zero.
		return expression.Imm(0)
	}
	res := r.regs[e.idx]
	if e.bits != 64 {
		res = expression.ZeroExtend(res, e.bits)
	}
	return res
}

// GetArmSP is like GetArm, except that X31/W31 is interpreted as SP/WSP, not XZR/WZR.
func (r *Registers) GetArmSP(reg arm64asm.RegSP) expression.Expression {
	e := regMappingForSP(reg)
	res := r.regs[e.idx]
	if e.bits != 64 {
		res = expression.ZeroExtend(res, e.bits)
	}
	return res
}

// Get returns the expression.Expression value associated with the given Reg register
func (r *Registers) Get(reg Reg) expression.Expression {
	if reg == XZR {
		// *ZR always reads zero.
		return expression.Imm(0)
	}
	if int(reg) >= len(r.regs) {
		return r.regs[0]
	}
	return r.regs[int(reg)]
}

// NameRegisterArm discards information about the expression currently stored in `reg`,
// replacing it with a name. This is useful if we want to track stores to the address
// contained in the register (e.g. if we know that at some point a register contains
// a pointer to an interesting variable, and later we want to find the offset at which something is stored
// in that variable.
//
// It may not be called on SP/WSP; calling it on XZR/WZR has no effect.
func (r *Registers) NameRegisterArm(reg arm64asm.Reg, name string) {
	r.setArm64asm(reg, expression.Named(name))
}
