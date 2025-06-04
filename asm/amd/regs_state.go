// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import (
	"errors"
	"fmt"
	"io"
	"math"

	"go.opentelemetry.io/ebpf-profiler/asm/variable"
	"golang.org/x/arch/x86/x86asm"
)

var debugPrinting = false

type regEntry struct {
	idx  int
	bits int
}

var regs [128]regEntry

func init() {
	regs[x86asm.AL] = regEntry{idx: 1, bits: 8}
	regs[x86asm.CL] = regEntry{idx: 2, bits: 8}
	regs[x86asm.DL] = regEntry{idx: 3, bits: 8}
	regs[x86asm.BL] = regEntry{idx: 4, bits: 8}
	regs[x86asm.SPB] = regEntry{idx: 5, bits: 8}
	regs[x86asm.BPB] = regEntry{idx: 6, bits: 8}
	regs[x86asm.SIB] = regEntry{idx: 7, bits: 8}
	regs[x86asm.DIB] = regEntry{idx: 8, bits: 8}
	regs[x86asm.R8B] = regEntry{idx: 9, bits: 8}
	regs[x86asm.R9B] = regEntry{idx: 10, bits: 8}
	regs[x86asm.R10B] = regEntry{idx: 11, bits: 8}
	regs[x86asm.R11B] = regEntry{idx: 12, bits: 8}
	regs[x86asm.R12B] = regEntry{idx: 13, bits: 8}
	regs[x86asm.R13B] = regEntry{idx: 14, bits: 8}
	regs[x86asm.R14B] = regEntry{idx: 15, bits: 8}
	regs[x86asm.R15B] = regEntry{idx: 16, bits: 8}

	regs[x86asm.AX] = regEntry{idx: 1, bits: 16}
	regs[x86asm.CX] = regEntry{idx: 2, bits: 16}
	regs[x86asm.DX] = regEntry{idx: 3, bits: 16}
	regs[x86asm.BX] = regEntry{idx: 4, bits: 16}
	regs[x86asm.SP] = regEntry{idx: 5, bits: 16}
	regs[x86asm.BP] = regEntry{idx: 6, bits: 16}
	regs[x86asm.SI] = regEntry{idx: 7, bits: 16}
	regs[x86asm.DI] = regEntry{idx: 8, bits: 16}
	regs[x86asm.R8W] = regEntry{idx: 9, bits: 16}
	regs[x86asm.R9W] = regEntry{idx: 10, bits: 16}
	regs[x86asm.R10W] = regEntry{idx: 11, bits: 16}
	regs[x86asm.R11W] = regEntry{idx: 12, bits: 16}
	regs[x86asm.R12W] = regEntry{idx: 13, bits: 16}
	regs[x86asm.R13W] = regEntry{idx: 14, bits: 16}
	regs[x86asm.R14W] = regEntry{idx: 15, bits: 16}
	regs[x86asm.R15W] = regEntry{idx: 16, bits: 16}

	regs[x86asm.EAX] = regEntry{idx: 1, bits: 32}
	regs[x86asm.ECX] = regEntry{idx: 2, bits: 32}
	regs[x86asm.EDX] = regEntry{idx: 3, bits: 32}
	regs[x86asm.EBX] = regEntry{idx: 4, bits: 32}
	regs[x86asm.ESP] = regEntry{idx: 5, bits: 32}
	regs[x86asm.EBP] = regEntry{idx: 6, bits: 32}
	regs[x86asm.ESI] = regEntry{idx: 7, bits: 32}
	regs[x86asm.EDI] = regEntry{idx: 8, bits: 32}
	regs[x86asm.R8L] = regEntry{idx: 9, bits: 32}
	regs[x86asm.R9L] = regEntry{idx: 10, bits: 32}
	regs[x86asm.R10L] = regEntry{idx: 11, bits: 32}
	regs[x86asm.R11L] = regEntry{idx: 12, bits: 32}
	regs[x86asm.R12L] = regEntry{idx: 13, bits: 32}
	regs[x86asm.R13L] = regEntry{idx: 14, bits: 32}
	regs[x86asm.R14L] = regEntry{idx: 15, bits: 32}
	regs[x86asm.R15L] = regEntry{idx: 16, bits: 32}

	regs[x86asm.RAX] = regEntry{idx: 1, bits: 64}
	regs[x86asm.RCX] = regEntry{idx: 2, bits: 64}
	regs[x86asm.RDX] = regEntry{idx: 3, bits: 64}
	regs[x86asm.RBX] = regEntry{idx: 4, bits: 64}
	regs[x86asm.RSP] = regEntry{idx: 5, bits: 64}
	regs[x86asm.RBP] = regEntry{idx: 6, bits: 64}
	regs[x86asm.RSI] = regEntry{idx: 7, bits: 64}
	regs[x86asm.RDI] = regEntry{idx: 8, bits: 64}
	regs[x86asm.R8] = regEntry{idx: 9, bits: 64}
	regs[x86asm.R9] = regEntry{idx: 10, bits: 64}
	regs[x86asm.R10] = regEntry{idx: 11, bits: 64}
	regs[x86asm.R11] = regEntry{idx: 12, bits: 64}
	regs[x86asm.R12] = regEntry{idx: 13, bits: 64}
	regs[x86asm.R13] = regEntry{idx: 14, bits: 64}
	regs[x86asm.R14] = regEntry{idx: 15, bits: 64}
	regs[x86asm.R15] = regEntry{idx: 16, bits: 64}

	regs[x86asm.RIP] = regEntry{idx: 17, bits: 64}
}

func regIndex(reg x86asm.Reg) int {
	e := regEntryFor(reg)
	return e.idx
}

func regEntryFor(reg x86asm.Reg) regEntry {
	if reg > 0 && int(reg) < len(regs) {
		e := regs[reg]
		return e
	}
	return regEntry{}
}

type RegsState struct {
	regs [18]variable.Expression
}

func (r *RegsState) Set(reg x86asm.Reg, v variable.Expression) {
	e := regEntryFor(reg)
	if e.bits != 64 {
		v = variable.ZeroExtend(v, e.bits)
	}
	if debugPrinting {
		if reg != x86asm.RIP {
			fmt.Printf("    [REG-W] %6s = %s\n", reg, v.DebugString())
		}
	}
	r.regs[e.idx] = v
}

func (r *RegsState) Get(reg x86asm.Reg) variable.Expression {
	e := regEntryFor(reg)
	res := r.regs[e.idx]
	if e.bits != 64 {
		res = variable.ZeroExtend(res, e.bits)
	}
	return res
}

func (r *RegsState) DebugString() string {
	res := ""
	res += "RAX: " + r.regs[regIndex(x86asm.RAX)].DebugString() + "\n"
	res += "RCX: " + r.regs[regIndex(x86asm.RCX)].DebugString() + "\n"
	res += "RDX: " + r.regs[regIndex(x86asm.RDX)].DebugString() + "\n"
	res += "RBX: " + r.regs[regIndex(x86asm.RBX)].DebugString() + "\n"
	res += "RSP: " + r.regs[regIndex(x86asm.RSP)].DebugString() + "\n"
	res += "RBP: " + r.regs[regIndex(x86asm.RBP)].DebugString() + "\n"
	res += "RSI: " + r.regs[regIndex(x86asm.RSI)].DebugString() + "\n"
	res += "RDI: " + r.regs[regIndex(x86asm.RDI)].DebugString() + "\n"
	res += "R8 : " + r.regs[regIndex(x86asm.R8)].DebugString() + "\n"
	res += "R9 : " + r.regs[regIndex(x86asm.R9)].DebugString() + "\n"
	res += "R10: " + r.regs[regIndex(x86asm.R10)].DebugString() + "\n"
	res += "R11: " + r.regs[regIndex(x86asm.R11)].DebugString() + "\n"
	res += "R12: " + r.regs[regIndex(x86asm.R12)].DebugString() + "\n"
	res += "R13: " + r.regs[regIndex(x86asm.R13)].DebugString() + "\n"
	res += "R14: " + r.regs[regIndex(x86asm.R14)].DebugString() + "\n"
	res += "R15: " + r.regs[regIndex(x86asm.R15)].DebugString() + "\n"
	res += "RIP: " + r.regs[regIndex(x86asm.RIP)].DebugString() + "\n"
	return res
}

type compare struct {
	left  variable.Expression
	right uint64
	jmp   x86asm.Op
}

type Interpreter struct {
	Regs        RegsState
	code        []byte
	CodeAddress variable.Expression
	pc          int

	Opt variable.Options

	cmp compare

	mem            map[variable.Expression]variable.Expression
	cmpConstraints []compare
}

func NewInterpreter() *Interpreter {
	it := &Interpreter{}
	it.initRegs()
	return it
}

func NewInterpreterWithCode(code []byte) *Interpreter {
	it := &Interpreter{code: code, CodeAddress: variable.Var("code address")}
	it.initRegs()
	return it
}

func (i *Interpreter) WithMemory() *Interpreter {
	i.mem = make(map[variable.Expression]variable.Expression)
	return i
}

func (i *Interpreter) WriteMem(at, v variable.Expression) {
	if i.mem != nil {
		if debugPrinting {
			fmt.Printf("    [W] %s = %s\n", at, v)
		}
		i.mem[at] = v
	}
}

func (i *Interpreter) ReadMem(at variable.Expression) (variable.Expression, bool) {
	for a, v := range i.mem {
		if a.Match(at) {
			return v, true
		}
	}
	return variable.Imm(0), false
}

func (i *Interpreter) ResetCode(code []byte, address variable.Expression) {
	i.code = code
	i.CodeAddress = address
	i.pc = 0
}

func (i *Interpreter) initRegs() {
	i.Regs.regs[0] = variable.Var("invalid reg")
	i.Regs.regs[regIndex(x86asm.RAX)] = variable.Var("initial RAX")
	i.Regs.regs[regIndex(x86asm.RCX)] = variable.Var("initial RCX")
	i.Regs.regs[regIndex(x86asm.RDX)] = variable.Var("initial RDX")
	i.Regs.regs[regIndex(x86asm.RBX)] = variable.Var("initial RBX")
	i.Regs.regs[regIndex(x86asm.RSP)] = variable.Var("initial RSP")
	i.Regs.regs[regIndex(x86asm.RBP)] = variable.Var("initial RBP")
	i.Regs.regs[regIndex(x86asm.RSI)] = variable.Var("initial RSI")
	i.Regs.regs[regIndex(x86asm.RDI)] = variable.Var("initial RDI")
	i.Regs.regs[regIndex(x86asm.R8)] = variable.Var("initial R8")
	i.Regs.regs[regIndex(x86asm.R9)] = variable.Var("initial R9")
	i.Regs.regs[regIndex(x86asm.R10)] = variable.Var("initial R10")
	i.Regs.regs[regIndex(x86asm.R11)] = variable.Var("initial R11")
	i.Regs.regs[regIndex(x86asm.R12)] = variable.Var("initial R12")
	i.Regs.regs[regIndex(x86asm.R13)] = variable.Var("initial R13")
	i.Regs.regs[regIndex(x86asm.R14)] = variable.Var("initial R14")
	i.Regs.regs[regIndex(x86asm.R15)] = variable.Var("initial R15")
	i.Regs.regs[regIndex(x86asm.RIP)] = variable.Var("initial RIP")
}

func (i *Interpreter) Loop() (x86asm.Inst, error) {
	return i.LoopWithBreak(func(x86asm.Inst) bool { return false })
}

func (i *Interpreter) LoopWithBreak(breakLoop func(op x86asm.Inst) bool) (x86asm.Inst, error) {
	prev := x86asm.Inst{}
	for j := 0; j < 137; j++ {
		op, err := i.Step()
		if err != nil {
			return prev, err
		}
		if breakLoop(op) {
			return op, nil
		}
		prev = op
	}
	return prev, errors.New("interpreter loop bound")
}

func (i *Interpreter) Step() (x86asm.Inst, error) {
	if len(i.code) == 0 {
		return x86asm.Inst{}, io.EOF
	}
	rem := i.code[i.pc:]
	if len(rem) == 0 {
		return x86asm.Inst{}, io.EOF
	}
	if ok, insnLen := DecodeSkippable(rem); ok {
		i.pc += insnLen
		return x86asm.Inst{Op: x86asm.NOP}, nil
	}
	inst, err := x86asm.Decode(rem, 64)
	if err != nil {
		return x86asm.Inst{}, fmt.Errorf("failed to decode instruction at 0x%x : %w",
			i.pc, err)
	}

	i.pc += inst.Len
	i.Regs.Set(x86asm.RIP, variable.Add(i.CodeAddress, variable.Imm(uint64(i.pc))))
	if debugPrinting {
		isnAddr := variable.Add(i.CodeAddress, variable.Imm(uint64(i.pc-inst.Len)))
		fmt.Printf("| %6s %s\n", isnAddr.DebugString(), x86asm.IntelSyntax(inst, uint64(i.pc), nil))
	}
	if inst.Op == x86asm.RET {
		return inst, nil
	}
	if inst.Op == x86asm.ADD {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, variable.Add(i.Regs.Get(dst), variable.Imm(uint64(src))))
			case x86asm.Reg:
				i.Regs.Set(dst, variable.Add(i.Regs.Get(dst), i.Regs.Get(src)))
			case x86asm.Mem:
				v := i.MemArg(i.Opt, src)
				v = variable.MemS(src.Segment, v, inst.MemBytes)
				i.Regs.Set(dst, variable.Add(i.Regs.Get(dst), v))
			}
		}
	}
	if inst.Op == x86asm.SHL {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, imm := inst.Args[1].(x86asm.Imm); imm {
				v := variable.MultiplyWithOptions(
					i.Opt,
					i.Regs.Get(dst),
					variable.Imm(uint64(math.Pow(2, float64(src)))),
				)
				i.Regs.Set(dst, v)
			}
		}
	}
	if inst.Op == x86asm.MOV || inst.Op == x86asm.MOVZX || inst.Op == x86asm.MOVSXD || inst.Op == x86asm.MOVSX {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, variable.Imm(uint64(src)))
			case x86asm.Reg:
				i.Regs.Set(dst, i.Regs.Get(src))
			case x86asm.Mem:
				v := i.MemArg(i.Opt, src)

				dataSizeBits := inst.DataSize

				if dataSizeBits == 64 {
					if m, memOk := i.ReadMem(v); memOk {
						v = m
					} else {
						v = variable.MemS(src.Segment, v, inst.MemBytes)
					}
				} else {
					v = variable.MemS(src.Segment, v, inst.MemBytes)
				}
				if inst.Op == x86asm.MOVSXD || inst.Op == x86asm.MOVSX {
					v = variable.SignExtend(v, dataSizeBits)
				} else {
					v = variable.ZeroExtend(v, dataSizeBits)
				}
				i.Regs.Set(dst, v)
			}
		}

		if dst, ok := inst.Args[0].(x86asm.Mem); ok {
			if i.mem != nil {
				dsta := i.MemArg(i.Opt, dst)
				switch src := inst.Args[1].(type) {
				case x86asm.Imm:
					i.WriteMem(dsta, variable.Imm(uint64(src)))
				case x86asm.Reg:
					i.WriteMem(dsta, i.Regs.Get(src))
				}
			}
		}
	}
	if inst.Op == x86asm.XOR {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, reg := inst.Args[1].(x86asm.Reg); reg {
				if src == dst {
					i.Regs.Set(dst, variable.Imm(0))
				}
			}
		}
	}
	if inst.Op == x86asm.AND {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, imm := inst.Args[1].(x86asm.Imm); imm {
				if src == 3 { // todo other cases
					i.Regs.Set(dst, variable.ZeroExtend(i.Regs.Get(dst), 2))
				}
			}
		}
	}
	if inst.Op == x86asm.LEA {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, mem := inst.Args[1].(x86asm.Mem); mem {
				v := i.MemArg(i.Opt, src)
				i.Regs.Set(dst, v)
			}
		}
	}
	if inst.Op == x86asm.CMP {
		if left, ok := inst.Args[0].(x86asm.Reg); ok {
			if right, mem := inst.Args[1].(x86asm.Imm); mem {
				i.compare(left, right)
			}
		}
	}
	if inst.Op == x86asm.JA || inst.Op == x86asm.JAE {
		i.saveCompareConstraint(inst.Op)
	}
	return inst, nil
}

func (i *Interpreter) MemArg(opt variable.Options, src x86asm.Mem) variable.Expression {
	vs := make([]variable.Expression, 0, 3)
	if src.Disp != 0 {
		vs = append(vs, variable.Imm(uint64(src.Disp)))
	}
	if src.Base != 0 {
		vs = append(vs, i.Regs.Get(src.Base))
	}
	if src.Index != 0 {
		v := variable.MultiplyWithOptions(
			opt,
			i.Regs.Get(src.Index),
			variable.Imm(uint64(src.Scale)),
		)
		vs = append(vs, v)
	}
	v := variable.Add(vs...)
	return v
}

func (i *Interpreter) compare(left x86asm.Reg, right x86asm.Imm) {
	i.cmp.left = i.Regs.Get(left)
	i.cmp.right = uint64(right)
	i.cmp.jmp = 0
}

func (i *Interpreter) saveCompareConstraint(inst x86asm.Op) {
	i.cmp.jmp = inst
	i.cmpConstraints = append(i.cmpConstraints, i.cmp)
	i.cmp = compare{}
}

func (i *Interpreter) MaxValue(of variable.Expression) uint64 {
	for _, cmp := range i.cmpConstraints {
		if cmp.left == nil { // unhandled compare instruction
			continue
		}
		if cmp.left.Match(of) {
			switch cmp.jmp {
			case x86asm.JAE:
				return cmp.right - 1
			case x86asm.JA:
				return cmp.right
			default:
				return of.MaxValue()
			}
		}
	}
	return of.MaxValue()
}

type CodeBlock struct {
	Address variable.Expression
	Code    []byte
}
