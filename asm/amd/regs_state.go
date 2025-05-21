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

const debugPrinting = false

type regIndexTableEntry struct {
	idx int
	sz  int
}

var regIndexTable [128]regIndexTableEntry

func init() {
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
	idx, sz := regIndexWithSize(reg)
	if sz != size64 {
		v = variable.Crop(v, sz)
	}
	if debugPrinting {
		if reg != x86asm.RIP {
			fmt.Printf("                               -> | %6s = %s\n", reg, v.String())
		}
	}
	r.regs[idx] = v
}

func (r *RegsState) Get(reg x86asm.Reg) variable.U64 {
	idx, sz := regIndexWithSize(reg)
	res := r.regs[idx]
	if sz != size64 {
		res = variable.Crop(res, sz)
	}
	return res
}

type Interpreter struct {
	Regs        RegsState
	code        []byte
	CodeAddress variable.U64
	pc          int
}

func NewInterpreter(code []byte) Interpreter {
	it := Interpreter{code: code, CodeAddress: variable.Var("code address")}
	it.initRegs()
	return it
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

func (i *Interpreter) Loop() error {
	return i.LoopWithBreak(nil)
}
func (i *Interpreter) LoopWithBreak(breakLoop func(op x86asm.Inst) bool) error {
	for j := 0; j < 137; j++ {
		op, err := i.Step()
		if err != nil {
			return err
		}
		if breakLoop != nil && breakLoop(op) {
			return nil
		}
	}
	return errors.New("interpreter loop bound")
}
func (i *Interpreter) Step() (x86asm.Inst, error) {
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
	if debugPrinting {
		fmt.Printf(" | %4x %s\n", i.pc, inst.String())
	}
	i.pc += inst.Len
	i.Regs.Set(x86asm.RIP, variable.Add(i.CodeAddress, variable.Imm(uint64(i.pc))))

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
				vs := make([]variable.U64, 0, 3)
				if src.Disp != 0 {
					vs = append(vs, variable.Imm(uint64(src.Disp)))
				}
				if src.Base != 0 {
					vs = append(vs, i.Regs.Get(src.Base))
				}
				if src.Index != 0 {
					v := variable.Mul(
						i.Regs.Get(src.Index),
						variable.Imm(uint64(src.Scale)),
					)
					vs = append(vs, v)
				}
				v := variable.Add(vs...)
				v = variable.MemS(src.Segment, v)
				i.Regs.Set(dst, variable.Add(i.Regs.Get(dst), v))
			}
		}
	}
	if inst.Op == x86asm.SHL {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, imm := inst.Args[1].(x86asm.Imm); imm {
				v := variable.Mul(
					i.Regs.Get(dst),
					variable.Imm(uint64(math.Pow(2, float64(src)))),
				)
				i.Regs.Set(dst, v)
			}
		}
	}
	if inst.Op == x86asm.MOV || inst.Op == x86asm.MOVZX {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			switch src := inst.Args[1].(type) {
			case x86asm.Imm:
				i.Regs.Set(dst, variable.Imm(uint64(src)))
			case x86asm.Reg:
				i.Regs.Set(dst, i.Regs.Get(src))
			case x86asm.Mem:
				vs := make([]variable.U64, 0, 3)
				if src.Disp != 0 {
					vs = append(vs, variable.Imm(uint64(src.Disp)))
				}
				if src.Base != 0 {
					vs = append(vs, i.Regs.Get(src.Base))
				}
				if src.Index != 0 {
					v := variable.Mul(
						i.Regs.Get(src.Index),
						variable.Imm(uint64(src.Scale)),
					)
					vs = append(vs, v)
				}
				v := variable.Add(vs...)
				v = variable.MemS(src.Segment, v)
				i.Regs.Set(dst, v)
			}
		}
	}
	if inst.Op == x86asm.XOR {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, reg := inst.Args[1].(x86asm.Reg); reg {
				i.Regs.Set(dst, variable.Xor(i.Regs.Get(dst), i.Regs.Get(src)))
			}
		}
	}
	if inst.Op == x86asm.LEA {
		if dst, ok := inst.Args[0].(x86asm.Reg); ok {
			if src, mem := inst.Args[1].(x86asm.Mem); mem {
				vs := make([]variable.U64, 0, 3)
				if src.Disp != 0 {
					vs = append(vs, variable.Imm(uint64(src.Disp)))
				}
				if src.Base != 0 {
					vs = append(vs, i.Regs.Get(src.Base))
				}
				if src.Index != 0 {
					v := variable.Mul(
						i.Regs.Get(src.Index),
						variable.Imm(uint64(src.Scale)),
					)
					vs = append(vs, v)
				}
				v := variable.Add(vs...)
				i.Regs.Set(dst, v)
			}
		}
	}
	return inst, nil
}
