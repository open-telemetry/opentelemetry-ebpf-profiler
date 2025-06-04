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

const (
	size64 = 64
	size32 = 32
	size16 = 16
	size08 = 8
)

var debugPrinting = false

type regIndexTableEntry struct {
	idx int
	sz  int
}

var regIndexTable [128]regIndexTableEntry

func init() {
	//todo size8, size16 does not zeroout msb, should we support this?
	//(this would require to make Var of variable size and support concat/crop ?)
	regIndexTable[x86asm.AL] = regIndexTableEntry{idx: 1, sz: size08}
	regIndexTable[x86asm.CL] = regIndexTableEntry{idx: 2, sz: size08}
	regIndexTable[x86asm.DL] = regIndexTableEntry{idx: 3, sz: size08}
	regIndexTable[x86asm.BL] = regIndexTableEntry{idx: 4, sz: size08}
	regIndexTable[x86asm.SPB] = regIndexTableEntry{idx: 5, sz: size08}
	regIndexTable[x86asm.BPB] = regIndexTableEntry{idx: 6, sz: size08}
	regIndexTable[x86asm.SIB] = regIndexTableEntry{idx: 7, sz: size08}
	regIndexTable[x86asm.DIB] = regIndexTableEntry{idx: 8, sz: size08}
	regIndexTable[x86asm.R8B] = regIndexTableEntry{idx: 9, sz: size08}
	regIndexTable[x86asm.R9B] = regIndexTableEntry{idx: 10, sz: size08}
	regIndexTable[x86asm.R10B] = regIndexTableEntry{idx: 11, sz: size08}
	regIndexTable[x86asm.R11B] = regIndexTableEntry{idx: 12, sz: size08}
	regIndexTable[x86asm.R12B] = regIndexTableEntry{idx: 13, sz: size08}
	regIndexTable[x86asm.R13B] = regIndexTableEntry{idx: 14, sz: size08}
	regIndexTable[x86asm.R14B] = regIndexTableEntry{idx: 15, sz: size08}
	regIndexTable[x86asm.R15B] = regIndexTableEntry{idx: 16, sz: size08}

	regIndexTable[x86asm.AX] = regIndexTableEntry{idx: 1, sz: size16}
	regIndexTable[x86asm.CX] = regIndexTableEntry{idx: 2, sz: size16}
	regIndexTable[x86asm.DX] = regIndexTableEntry{idx: 3, sz: size16}
	regIndexTable[x86asm.BX] = regIndexTableEntry{idx: 4, sz: size16}
	regIndexTable[x86asm.SP] = regIndexTableEntry{idx: 5, sz: size16}
	regIndexTable[x86asm.BP] = regIndexTableEntry{idx: 6, sz: size16}
	regIndexTable[x86asm.SI] = regIndexTableEntry{idx: 7, sz: size16}
	regIndexTable[x86asm.DI] = regIndexTableEntry{idx: 8, sz: size16}
	regIndexTable[x86asm.R8W] = regIndexTableEntry{idx: 9, sz: size16}
	regIndexTable[x86asm.R9W] = regIndexTableEntry{idx: 10, sz: size16}
	regIndexTable[x86asm.R10W] = regIndexTableEntry{idx: 11, sz: size16}
	regIndexTable[x86asm.R11W] = regIndexTableEntry{idx: 12, sz: size16}
	regIndexTable[x86asm.R12W] = regIndexTableEntry{idx: 13, sz: size16}
	regIndexTable[x86asm.R13W] = regIndexTableEntry{idx: 14, sz: size16}
	regIndexTable[x86asm.R14W] = regIndexTableEntry{idx: 15, sz: size16}
	regIndexTable[x86asm.R15W] = regIndexTableEntry{idx: 16, sz: size16}

	regIndexTable[x86asm.EAX] = regIndexTableEntry{idx: 1, sz: size32}
	regIndexTable[x86asm.ECX] = regIndexTableEntry{idx: 2, sz: size32}
	regIndexTable[x86asm.EDX] = regIndexTableEntry{idx: 3, sz: size32}
	regIndexTable[x86asm.EBX] = regIndexTableEntry{idx: 4, sz: size32}
	regIndexTable[x86asm.ESP] = regIndexTableEntry{idx: 5, sz: size32}
	regIndexTable[x86asm.EBP] = regIndexTableEntry{idx: 6, sz: size32}
	regIndexTable[x86asm.ESI] = regIndexTableEntry{idx: 7, sz: size32}
	regIndexTable[x86asm.EDI] = regIndexTableEntry{idx: 8, sz: size32}
	regIndexTable[x86asm.R8L] = regIndexTableEntry{idx: 9, sz: size32}
	regIndexTable[x86asm.R9L] = regIndexTableEntry{idx: 10, sz: size32}
	regIndexTable[x86asm.R10L] = regIndexTableEntry{idx: 11, sz: size32}
	regIndexTable[x86asm.R11L] = regIndexTableEntry{idx: 12, sz: size32}
	regIndexTable[x86asm.R12L] = regIndexTableEntry{idx: 13, sz: size32}
	regIndexTable[x86asm.R13L] = regIndexTableEntry{idx: 14, sz: size32}
	regIndexTable[x86asm.R14L] = regIndexTableEntry{idx: 15, sz: size32}
	regIndexTable[x86asm.R15L] = regIndexTableEntry{idx: 16, sz: size32}

	regIndexTable[x86asm.RAX] = regIndexTableEntry{idx: 1, sz: size64}
	regIndexTable[x86asm.RCX] = regIndexTableEntry{idx: 2, sz: size64}
	regIndexTable[x86asm.RDX] = regIndexTableEntry{idx: 3, sz: size64}
	regIndexTable[x86asm.RBX] = regIndexTableEntry{idx: 4, sz: size64}
	regIndexTable[x86asm.RSP] = regIndexTableEntry{idx: 5, sz: size64}
	regIndexTable[x86asm.RBP] = regIndexTableEntry{idx: 6, sz: size64}
	regIndexTable[x86asm.RSI] = regIndexTableEntry{idx: 7, sz: size64}
	regIndexTable[x86asm.RDI] = regIndexTableEntry{idx: 8, sz: size64}
	regIndexTable[x86asm.R8] = regIndexTableEntry{idx: 9, sz: size64}
	regIndexTable[x86asm.R9] = regIndexTableEntry{idx: 10, sz: size64}
	regIndexTable[x86asm.R10] = regIndexTableEntry{idx: 11, sz: size64}
	regIndexTable[x86asm.R11] = regIndexTableEntry{idx: 12, sz: size64}
	regIndexTable[x86asm.R12] = regIndexTableEntry{idx: 13, sz: size64}
	regIndexTable[x86asm.R13] = regIndexTableEntry{idx: 14, sz: size64}
	regIndexTable[x86asm.R14] = regIndexTableEntry{idx: 15, sz: size64}
	regIndexTable[x86asm.R15] = regIndexTableEntry{idx: 16, sz: size64}

	regIndexTable[x86asm.RIP] = regIndexTableEntry{idx: 17, sz: size64}
}

func regIndex(reg x86asm.Reg) int {
	idx, _ := regIndexWithSize(reg)
	return idx
}

func regIndexWithSize(reg x86asm.Reg) (idx, size int) {
	if reg > 0 && int(reg) < len(regIndexTable) {
		e := regIndexTable[reg]
		return e.idx, e.sz
	}
	return 0, 0
}

type RegsState struct {
	regs [18]variable.U64
}

func (r *RegsState) Set(reg x86asm.Reg, v variable.U64) {
	idx, _ := regIndexWithSize(reg)
	//if sz != size64 {
	//	v = variable.ZeroExtend(v, sz)
	//}
	if debugPrinting {
		if reg != x86asm.RIP {
			fmt.Printf("    [REG-W] %6s = %s\n", reg, v.String())
		}
	}
	r.regs[idx] = v
}

func (r *RegsState) Get(reg x86asm.Reg) variable.U64 {
	idx, sz := regIndexWithSize(reg)
	res := r.regs[idx]
	if sz != size64 {
		res = variable.ZeroExtend(res, sz)
	}
	return res
}

func (r *RegsState) DebugString() string {
	res := ""
	res += "RAX: " + r.regs[regIndex(x86asm.RAX)].String() + "\n"
	res += "RCX: " + r.regs[regIndex(x86asm.RCX)].String() + "\n"
	res += "RDX: " + r.regs[regIndex(x86asm.RDX)].String() + "\n"
	res += "RBX: " + r.regs[regIndex(x86asm.RBX)].String() + "\n"
	res += "RSP: " + r.regs[regIndex(x86asm.RSP)].String() + "\n"
	res += "RBP: " + r.regs[regIndex(x86asm.RBP)].String() + "\n"
	res += "RSI: " + r.regs[regIndex(x86asm.RSI)].String() + "\n"
	res += "RDI: " + r.regs[regIndex(x86asm.RDI)].String() + "\n"
	res += "R8 : " + r.regs[regIndex(x86asm.R8)].String() + "\n"
	res += "R9 : " + r.regs[regIndex(x86asm.R9)].String() + "\n"
	res += "R10: " + r.regs[regIndex(x86asm.R10)].String() + "\n"
	res += "R11: " + r.regs[regIndex(x86asm.R11)].String() + "\n"
	res += "R12: " + r.regs[regIndex(x86asm.R12)].String() + "\n"
	res += "R13: " + r.regs[regIndex(x86asm.R13)].String() + "\n"
	res += "R14: " + r.regs[regIndex(x86asm.R14)].String() + "\n"
	res += "R15: " + r.regs[regIndex(x86asm.R15)].String() + "\n"
	res += "RIP: " + r.regs[regIndex(x86asm.RIP)].String() + "\n"
	return res
}

type compare struct {
	left  variable.U64
	right uint64
	//cmpRIP variable.U64
	jmp x86asm.Op
}

type Interpreter struct {
	Regs        RegsState
	code        []byte
	CodeAddress variable.U64
	pc          int

	Opt variable.Options

	cmp compare

	mem            map[variable.U64]variable.U64
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
	i.mem = make(map[variable.U64]variable.U64)
	return i
}

func (i *Interpreter) WriteMem(at, v variable.U64) {
	if i.mem != nil {
		if debugPrinting {
			fmt.Printf("    [W] %s = %s\n", at, v)
		}
		i.mem[at] = v
	}
}

func (i *Interpreter) ReadMem(at variable.U64, debug bool) (variable.U64, bool) {
	if debugPrinting && debug {
		//fmt.Printf("    [R] %s\n", at.String())
	}
	for a, v := range i.mem {
		//fmt.Printf("    |- [R] test %s\n", a.String())
		if a.Eval(at) {
			return v, true
		}
	}
	return variable.Imm(0), false
}

func (i *Interpreter) ResetCode(code []byte, address variable.U64) {
	i.code = code
	i.CodeAddress = address
	i.pc = 0
}

func (i *Interpreter) initRegs() {
	i.Regs.regs[0] = variable.Var("invali reg")
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
	return i.LoopWithBreak(nil)
}

func (i *Interpreter) LoopWithBreak(breakLoop func(op x86asm.Inst) bool) (x86asm.Inst, error) {
	prev := x86asm.Inst{}
	for j := 0; j < 137; j++ {
		op, err := i.Step()
		if err != nil {
			return prev, err
		}
		if breakLoop != nil && breakLoop(op) {
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
	bp := false
	if debugPrinting {
		isnAddr := variable.Add(i.CodeAddress, variable.Imm(uint64(i.pc-inst.Len)))
		fmt.Printf("| %6s %s\n", isnAddr.String(), x86asm.IntelSyntax(inst, uint64(i.pc), nil))
		if "0x1bee05" == isnAddr.String() {
			bp = true
		}
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
					if m, memOk := i.ReadMem(v, bp); memOk {
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

func (i *Interpreter) MemArg(opt variable.Options, src x86asm.Mem) variable.U64 {
	vs := make([]variable.U64, 0, 3)
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

func (i *Interpreter) MaxValue(of variable.U64) uint64 {
	for _, cmp := range i.cmpConstraints {
		if cmp.left == nil { // unhandled compare instruction
			continue
		}
		if cmp.left.Eval(of) {
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
	Address variable.U64
	Code    []byte
}
