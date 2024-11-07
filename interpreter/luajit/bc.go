// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

// See https://github.com/openresty/luajit2/blob/7952882d/src/lj_bc.h#L34

var bcMode = []uint16{
	0x3183, 0x3183, 0x3983, 0x3983, 0x2183, 0x2183, 0x2503, 0x2503,
	0x2483, 0x2483, 0x2403, 0x2403, 0xb181, 0xb181, 0xb180, 0xb180,
	0xb303, 0xb303, 0xb181, 0xb181, 0x8181, 0x2981, 0x5499, 0x5c99,
	0x6499, 0x6c99, 0x7499, 0x5499, 0x5c99, 0x6499, 0x6c99, 0x7499,
	0x5199, 0x5999, 0x6199, 0x6999, 0x7199, 0x7999, 0x4221, 0xb501,
	0xb701, 0xb381, 0xb481, 0xb401, 0xb102, 0xb281, 0xb185, 0xb505,
	0xb485, 0xb405, 0xb684, 0x1601, 0x1301, 0x1581, 0x0501, 0x0d03,
	0x0199, 0x0519, 0x0319, 0x0199, 0x099b, 0x0d1b, 0x0b1b, 0x0c82,
	0x099b, 0x4b32, 0x4b32, 0x4b02, 0x4b02, 0x4b32, 0x4b32, 0xb332,
	0xb682, 0xb302, 0xb304, 0xb304, 0xb304, 0xb682, 0xb682, 0xb682,
	0xb682, 0xb302, 0xb682, 0xb682, 0xb302, 0xb684, 0xb684, 0xb304,
	0xb684, 0xb004, 0xb004, 0xb304, 0xb004, 0xb004, 0xb304, 0xb004,
	0xb004}

func bcOp(ins uint32) uint32 {
	return ins & 0xff
}

func bcModeMM(op uint32) uint32 {
	return uint32(bcMode[op] >> 11)
}

func bcModeA(op uint32) uint32 {
	return uint32(bcMode[op] & 7)
}

func bcA(ins uint32) uint32 {
	return (ins >> 8) & 0xff
}

func bcB(ins uint32) uint32 {
	return ins >> 24
}

func bcC(ins uint32) uint32 {
	return (ins >> 16) & 0xff
}

func bcD(ins uint32) uint32 {
	return ins >> 16
}

// Return the register used to store the function called at pc or metaname if it's a metamethod
func getSlotOrMetaname(ins uint32) (slot uint32, metaname string) {
	op := bcOp(ins)
	mm := bcModeMM(op)
	if mm == MMcall {
		slot := bcA(ins)
		if bcOp(ins) == BC_ITERC {
			slot -= 3
		}
		return slot, ""
	} else if mm != MMMax {
		return 0, ljMetaNames[mm]
	}
	return 0, ""
}
func bcModeAIsBase(op uint32) bool {
	return bcModeA(op) == BCMbase
}
func bcModeAIsDst(op uint32) bool {
	return bcModeA(op) == BCMdst
}

var ljMetaNames = []string{
	"index", "newindex", "gc",
	"mode", "eq", "len", "lt", "le", "concat",
	"call", "add", "sub", "mul", "div", "mod", "pow", "unm",
	"metatable", "tostring", "new", "pairs",
	"ipairs",
}

const (
	BCMdst  = 1
	BCMbase = 2
	MMcall  = 9
	MMMax   = 0x16
)

//nolint:revive,stylecheck
const (
	BC_ISLT = iota
	BC_ISGE
	BC_ISLE
	BC_ISGT
	BC_ISEQV
	BC_ISNEV
	BC_ISEQS
	BC_ISNES
	BC_ISEQN
	BC_ISNEN
	BC_ISEQP
	BC_ISNEP
	BC_ISTC
	BC_ISFC
	BC_IST
	BC_ISF
	BC_ISTYPE
	BC_ISNUM
	BC_MOV
	BC_NOT
	BC_UNM
	BC_LEN
	BC_ADDVN
	BC_SUBVN
	BC_MULVN
	BC_DIVVN
	BC_MODVN
	BC_ADDNV
	BC_SUBNV
	BC_MULNV
	BC_DIVNV
	BC_MODNV
	BC_ADDVV
	BC_SUBVV
	BC_MULVV
	BC_DIVVV
	BC_MODVV
	BC_POW
	BC_CAT
	BC_KSTR
	BC_KCDATA
	BC_KSHORT
	BC_KNUM
	BC_KPRI
	BC_KNIL
	BC_UGET
	BC_USETV
	BC_USETS
	BC_USETN
	BC_USETP
	BC_UCLO
	BC_FNEW
	BC_TNEW
	BC_TDUP
	BC_GGET
	BC_GSET
	BC_TGETV
	BC_TGETS
	BC_TGETB
	BC_TGETR
	BC_TSETV
	BC_TSETS
	BC_TSETB
	BC_TSETM
	BC_TSETR
	BC_CALLM
	BC_CALL
	BC_CALLMT
	BC_CALLT
	BC_ITERC
	BC_ITERN
	BC_VARG
	BC_ISNEXT
	BC_RETM
	BC_RET
	BC_RET0
	BC_RET1
	BC_FORI
	BC_JFORI
	BC_FORL
	BC_IFORL
	BC_JFORL
	BC_ITERL
	BC_IITERL
	BC_JITERL
	BC_LOOP
	BC_ILOOP
	BC_JLOOP
	BC_JMP
	BC_FUNCF
	BC_IFUNCF
	BC_JFUNCF
	BC_FUNCV
	BC_IFUNCV
	BC_JFUNCV
	BC_FUNCC
	BC_FUNCCW
	BC__MAX
)
