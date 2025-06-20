// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import (
	"fmt"
	"io"
	"math"

	"go.opentelemetry.io/ebpf-profiler/asm/expression"
	"golang.org/x/arch/x86/x86asm"
)

type CodeBlock struct {
	Address expression.Expression
	Code    []byte
}

type Registers struct {
	regs [18]expression.Expression
}

type Interpreter struct {
	Regs        Registers
	code        []byte
	CodeAddress expression.Expression
	pc          int
}

type regEntry struct {
	idx  int
	bits int
}

func regMappingFor(reg x86asm.Reg) regEntry {
	switch reg {
	case x86asm.AL:
		return regEntry{idx: 1, bits: 8}
	case x86asm.CL:
		return regEntry{idx: 2, bits: 8}
	case x86asm.DL:
		return regEntry{idx: 3, bits: 8}
	case x86asm.BL:
		return regEntry{idx: 4, bits: 8}
	case x86asm.SPB:
		return regEntry{idx: 5, bits: 8}
	case x86asm.BPB:
		return regEntry{idx: 6, bits: 8}
	case x86asm.SIB:
		return regEntry{idx: 7, bits: 8}
	case x86asm.DIB:
		return regEntry{idx: 8, bits: 8}
	case x86asm.R8B:
		return regEntry{idx: 9, bits: 8}
	case x86asm.R9B:
		return regEntry{idx: 10, bits: 8}
	case x86asm.R10B:
		return regEntry{idx: 11, bits: 8}
	case x86asm.R11B:
		return regEntry{idx: 12, bits: 8}
	case x86asm.R12B:
		return regEntry{idx: 13, bits: 8}
	case x86asm.R13B:
		return regEntry{idx: 14, bits: 8}
	case x86asm.R14B:
		return regEntry{idx: 15, bits: 8}
	case x86asm.R15B:
		return regEntry{idx: 16, bits: 8}
	case x86asm.AX:
		return regEntry{idx: 1, bits: 16}
	case x86asm.CX:
		return regEntry{idx: 2, bits: 16}
	case x86asm.DX:
		return regEntry{idx: 3, bits: 16}
	case x86asm.BX:
		return regEntry{idx: 4, bits: 16}
	case x86asm.SP:
		return regEntry{idx: 5, bits: 16}
	case x86asm.BP:
		return regEntry{idx: 6, bits: 16}
	case x86asm.SI:
		return regEntry{idx: 7, bits: 16}
	case x86asm.DI:
		return regEntry{idx: 8, bits: 16}
	case x86asm.R8W:
		return regEntry{idx: 9, bits: 16}
	case x86asm.R9W:
		return regEntry{idx: 10, bits: 16}
	case x86asm.R10W:
		return regEntry{idx: 11, bits: 16}
	case x86asm.R11W:
		return regEntry{idx: 12, bits: 16}
	case x86asm.R12W:
		return regEntry{idx: 13, bits: 16}
	case x86asm.R13W:
		return regEntry{idx: 14, bits: 16}
	case x86asm.R14W:
		return regEntry{idx: 15, bits: 16}
	case x86asm.R15W:
		return regEntry{idx: 16, bits: 16}
	case x86asm.EAX:
		return regEntry{idx: 1, bits: 32}
	case x86asm.ECX:
		return regEntry{idx: 2, bits: 32}
	case x86asm.EDX:
		return regEntry{idx: 3, bits: 32}
	case x86asm.EBX:
		return regEntry{idx: 4, bits: 32}
	case x86asm.ESP:
		return regEntry{idx: 5, bits: 32}
	case x86asm.EBP:
		return regEntry{idx: 6, bits: 32}
	case x86asm.ESI:
		return regEntry{idx: 7, bits: 32}
	case x86asm.EDI:
		return regEntry{idx: 8, bits: 32}
	case x86asm.R8L:
		return regEntry{idx: 9, bits: 32}
	case x86asm.R9L:
		return regEntry{idx: 10, bits: 32}
	case x86asm.R10L:
		return regEntry{idx: 11, bits: 32}
	case x86asm.R11L:
		return regEntry{idx: 12, bits: 32}
	case x86asm.R12L:
		return regEntry{idx: 13, bits: 32}
	case x86asm.R13L:
		return regEntry{idx: 14, bits: 32}
	case x86asm.R14L:
		return regEntry{idx: 15, bits: 32}
	case x86asm.R15L:
		return regEntry{idx: 16, bits: 32}
	case x86asm.RAX:
		return regEntry{idx: 1, bits: 64}
	case x86asm.RCX:
		return regEntry{idx: 2, bits: 64}
	case x86asm.RDX:
		return regEntry{idx: 3, bits: 64}
	case x86asm.RBX:
		return regEntry{idx: 4, bits: 64}
	case x86asm.RSP:
		return regEntry{idx: 5, bits: 64}
	case x86asm.RBP:
		return regEntry{idx: 6, bits: 64}
	case x86asm.RSI:
		return regEntry{idx: 7, bits: 64}
	case x86asm.RDI:
		return regEntry{idx: 8, bits: 64}
	case x86asm.R8:
		return regEntry{idx: 9, bits: 64}
	case x86asm.R9:
		return regEntry{idx: 10, bits: 64}
	case x86asm.R10:
		return regEntry{idx: 11, bits: 64}
	case x86asm.R11:
		return regEntry{idx: 12, bits: 64}
	case x86asm.R12:
		return regEntry{idx: 13, bits: 64}
	case x86asm.R13:
		return regEntry{idx: 14, bits: 64}
	case x86asm.R14:
		return regEntry{idx: 15, bits: 64}
	case x86asm.R15:
		return regEntry{idx: 16, bits: 64}
	case x86asm.RIP:
		return regEntry{idx: 17, bits: 64}
	default:
		return regEntry{idx: 0, bits: 64}
	}
}

func (r *Registers) Set(reg x86asm.Reg, v expression.Expression) {
	e := regMappingFor(reg)
	if e.bits != 64 {
		v = expression.ZeroExtend(v, e.bits)
	}
	r.regs[e.idx] = v
}

func (r *Registers) Get(reg x86asm.Reg) expression.Expression {
	e := regMappingFor(reg)
	res := r.regs[e.idx]
	if e.bits != 64 {
		res = expression.ZeroExtend(res, e.bits)
	}
	return res
}

func NewInterpreter() *Interpreter {
	it := &Interpreter{}
	it.initRegs()
	return it
}

func NewInterpreterWithCode(code []byte) *Interpreter {
	it := &Interpreter{code: code, CodeAddress: expression.Var("code address")}
	it.initRegs()
	return it
}

func (i *Interpreter) ResetCode(code []byte, address expression.Expression) {
	i.code = code
	i.CodeAddress = address
	i.pc = 0
}

func (i *Interpreter) Loop() (x86asm.Inst, error) {
	return i.LoopWithBreak(func(x86asm.Inst) bool { return false })
}

func (i *Interpreter) LoopWithBreak(breakLoop func(op x86asm.Inst) bool) (x86asm.Inst, error) {
	prev := x86asm.Inst{}
	for {
		op, err := i.Step()
		if err != nil {
			return prev, err
		}
		if breakLoop(op) {
			return op, nil
		}
		prev = op
	}
}

func (i *Interpreter) Step() (x86asm.Inst, error) {
	if len(i.code) == 0 {
		return x86asm.Inst{}, io.EOF
	}
	var inst x86asm.Inst
	var err error
	if ok, instLen := DecodeSkippable(i.code); ok {
		inst = x86asm.Inst{Op: x86asm.NOP, Len: instLen}
	} else {
		inst, err = x86asm.Decode(i.code, 64)
		if err != nil {
			return inst, fmt.Errorf("at 0x%x : %v", i.pc, err)
		}
	}
	i.pc += inst.Len
	i.code = i.code[inst.Len:]
	i.Regs.Set(x86asm.RIP, expression.Add(i.CodeAddress, expression.Imm(uint64(i.pc))))
	switch inst.Op {
	case x86asm.ADD:
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, expression.Add(i.Regs.Get(dst), expression.Imm(uint64(src))))
			case x86asm.Reg:
				i.Regs.Set(dst, expression.Add(i.Regs.Get(dst), i.Regs.Get(src)))
			case x86asm.Mem:
				v := i.MemArg(src)
				v = expression.MemWithSegment(src.Segment, v, inst.MemBytes)
				i.Regs.Set(dst, expression.Add(i.Regs.Get(dst), v))
			}
		}
	case x86asm.SHL:
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, imm := inst.Args[1].(x86asm.Imm); imm {
				v := expression.Multiply(
					i.Regs.Get(dst),
					expression.Imm(uint64(math.Pow(2, float64(src)))),
				)
				i.Regs.Set(dst, v)
			}
		}
	case x86asm.MOV, x86asm.MOVZX, x86asm.MOVSXD, x86asm.MOVSX:
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, expression.Imm(uint64(src)))
			case x86asm.Reg:
				i.Regs.Set(dst, i.Regs.Get(src))
			case x86asm.Mem:
				v := i.MemArg(src)

				dataSizeBits := inst.DataSize

				v = expression.MemWithSegment(src.Segment, v, inst.MemBytes)
				if inst.Op == x86asm.MOVSXD || inst.Op == x86asm.MOVSX {
					v = expression.SignExtend(v, dataSizeBits)
				} else {
					v = expression.ZeroExtend(v, dataSizeBits)
				}
				i.Regs.Set(dst, v)
			}
		}

	case x86asm.XOR:
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, reg := inst.Args[1].(x86asm.Reg); reg {
				if src == dst {
					i.Regs.Set(dst, expression.Imm(0))
				}
			}
		}
	case x86asm.AND:
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, imm := inst.Args[1].(x86asm.Imm); imm {
				if src == 3 { // todo other cases
					i.Regs.Set(dst, expression.ZeroExtend(i.Regs.Get(dst), 2))
				}
			}
		}
	case x86asm.LEA:
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, mem := inst.Args[1].(x86asm.Mem); mem {
				v := i.MemArg(src)
				i.Regs.Set(dst, v)
			}
		}
	case x86asm.NOP, x86asm.RET:
	default:
		return inst, nil
	}
	return inst, nil
}

func (i *Interpreter) MemArg(src x86asm.Mem) expression.Expression {
	vs := make([]expression.Expression, 0, 3)
	if src.Disp != 0 {
		vs = append(vs, expression.Imm(uint64(src.Disp)))
	}
	if src.Base != 0 {
		vs = append(vs, i.Regs.Get(src.Base))
	}
	if src.Index != 0 {
		v := expression.Multiply(
			i.Regs.Get(src.Index),
			expression.Imm(uint64(src.Scale)),
		)
		vs = append(vs, v)
	}
	v := expression.Add(vs...)
	return v
}

func (i *Interpreter) initRegs() {
	for j := 0; j < len(i.Regs.regs); j++ {
		i.Regs.regs[j] = expression.Var(fmt.Sprintf("initial reg #%d", j))
	}
}
