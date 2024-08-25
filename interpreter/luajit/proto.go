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

import (
	"errors"
	"unicode/utf8"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const (
	sizeofGCstr   = 24
	sizeofGCproto = 104
	stringGCType  = 4
	//https://github.com/openresty/luajit2/blob/7952882d/src/lj_def.h#L66
	byteCodeMax = 1 << 26
)

type GCobj struct {
	_   uint64 // nextgc
	_   byte   // marked
	gct byte
}

// GCproto minus first 8 bytes
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_obj.h#L372
// All the pointers (except chunkname) are pointers to extra space at the end of the GCproto object
// so we could try to be clever and read the whole thing at once if we needed to reduce remotememory
// traffic.
type protoRaw struct {
	// nextgc uint64    /*      0      |       8 */
	_      byte   /*      8      |       1 */
	_      byte   /*      9      |       1 */
	_      byte   /*     10      |       1 */
	_      byte   /*     11      |       1 */
	sizebc uint32 /*     12      |       4 */
	_      uint32 /*     16      |       4 */
	/* XXX  4-byte hole      */
	_         uint64        /*     24      |       8 */
	k         libpf.Address /*     32      |       8 */
	_         uint64        /*     40      |       8 */
	sizekgc   uint32        /*     48      |       4 */
	_         uint32        /*     52      |       4 */
	sizept    uint32        /*     56      |       4 */
	sizeuv    uint8         /*     60      |       1 */
	_         uint8         /*     61      |       1 */
	_         uint16        /*     62      |       2 */
	chunkname libpf.Address /*     64      |       8 */
	firstline uint32        /*     72      |       4 */
	numline   uint32        /*     76      |       4 */
	lineinfo  libpf.Address /*     80      |       8 */
	uvinfo    libpf.Address /*     88      |       8 */
	varinfo   libpf.Address /*     96      |       8 */
}

// proto is a userland cached version of LuaJIT's GCproto object which is
// contains all the static data for a function. A function on the stack
// will be a GCfunc which is basically a GCproto pointer and any captured
// upvalues.
type proto struct {
	protoRaw
	ptAddr       libpf.Address
	name         string
	bc           []uint32
	lineinfo8    []uint8
	lineinfo16   []uint16
	lineinfo32   []uint32
	upvalueNames []string
	varinforaw   []byte
	constants    []string
}

// newProto creates a proto from a GCproto* by reading memory remotely.
func newProto(rm remotememory.RemoteMemory, pt libpf.Address) (*proto, error) {
	p := &proto{ptAddr: pt}
	if err := rm.Read(pt+8, libpf.SliceFrom(&p.protoRaw)); err != nil {
		return nil, err
	}

	// reading memory from a remote process is always dicey, validate
	// we're looking at a GCproto object by checking that the debugging
	// info pointers are valid internal pointers or NULL.
	end := pt + libpf.Address(p.sizept)
	bad := func(addr libpf.Address) bool {
		return addr != 0 && (addr < pt || addr >= end)
	}
	if bad(p.lineinfo) || bad(p.uvinfo) || bad(p.varinfo) {
		return nil, errors.New("invalid GCproto object")
	}

	// string data is stored after the GCstr object
	p.name = rm.String(p.chunkname + sizeofGCstr)
	if !utf8.ValidString(p.name) {
		return nil, errors.New("invalid chunkname string")
	}

	// This should never be empty string.
	if p.name == "" {
		return nil, errors.New("invalid chunkname string")
	}

	if p.sizebc == 0 || p.sizebc > byteCodeMax {
		return nil, errors.New("invalid bytecode size")
	}

	p.bc = make([]uint32, p.sizebc)
	// bytecode starts at end of GCproto object
	// https://github.com/openresty/luajit2/blob/7952882d/src/lj_obj.h#L420
	if err := rm.Read(p.ptAddr+sizeofGCproto, libpf.SliceFrom(p.bc)); err != nil {
		return nil, err
	}
	if p.lineinfo != 0 {
		if p.numline < 256 {
			p.lineinfo8 = make([]uint8, p.sizebc)
			if err := rm.Read(p.lineinfo, libpf.SliceFrom(p.lineinfo8)); err != nil {
				return nil, err
			}
		} else if p.numline < 65536 {
			p.lineinfo16 = make([]uint16, p.sizebc)
			if err := rm.Read(p.lineinfo, libpf.SliceFrom(p.lineinfo16)); err != nil {
				return nil, err
			}
		} else {
			p.lineinfo32 = make([]uint32, p.sizebc)
			if err := rm.Read(p.lineinfo, libpf.SliceFrom(p.lineinfo32)); err != nil {
				return nil, err
			}
		}
	}

	if p.sizekgc > 0 {
		objs := make([]libpf.Address, p.sizekgc)
		p.constants = make([]string, p.sizekgc)
		if err := rm.Read(p.k-libpf.Address(p.sizekgc*8), libpf.SliceFrom(objs)); err != nil {
			return nil, err
		}
		for i, c := range objs {
			var gco GCobj
			if err := rm.Read(c, libpf.SliceFrom(&gco)); err != nil {
				return nil, err
			}
			if gco.gct == stringGCType {
				str := rm.String(objs[i] + sizeofGCstr)
				p.constants[len(objs)-i-1] = str
			}
		}
	}

	//https://github.com/openresty/luajit2/blob/7952882d/src/lj_debug.c#L225
	if p.uvinfo != 0 {
		// lineinfo/uvinfo/varinfo are all either null or set so we can calculate lengths from them
		lenuv := p.varinfo - p.uvinfo
		b := make([]byte, lenuv)
		if err := rm.Read(p.uvinfo, libpf.SliceFrom(b)); err != nil {
			return nil, err
		}
		p.upvalueNames = []string{}
		for len(b) > 0 {
			var name string
			b, name = parseString(b)
			b = b[1:] // skip null terminator
			p.upvalueNames = append(p.upvalueNames, name)
		}
		if p.sizeuv != uint8(len(p.upvalueNames)) {
			return nil, errors.New("invalid upvalue count")
		}
	}

	// varinfo is a pointer to data colocated with GCproto, its at the end
	// and its length isn't stored, but it can be derived by subtracting the
	// end of the object from the varinfo pointer.
	if p.varinfo != 0 {
		varinfolen := (p.ptAddr + libpf.Address(p.sizept)) - p.varinfo
		p.varinforaw = make([]byte, varinfolen)
		if err := rm.Read(p.varinfo, libpf.SliceFrom(p.varinforaw)); err != nil {
			return nil, err
		}
	}

	return p, nil
}

func (p *proto) getName() string {
	if p == nil {
		return ""
	}
	return p.name
}

// https://github.com/openresty/luajit2/blob/7952882d/src/lj_debug.c#L123
func (p *proto) getLine(pc uint32) uint32 {
	if p == nil || p.lineinfo == 0 || pc > p.sizebc || pc == 0 {
		return 0
	}
	first := p.firstline
	if pc == p.sizebc {
		return first + p.numline
	}
	pc--
	if pc == 0 {
		return first
	}
	if p.numline < 256 {
		return first + uint32(p.lineinfo8[pc])
	} else if p.numline < 65536 {
		return first + uint32(p.lineinfo16[pc])
	}
	return first + p.lineinfo32[pc]
}

func (p *proto) getVarname(slot, pc uint32) string {
	return parseVarinfo(p.varinforaw, pc, slot)
}

func (p *proto) getUpvalueName(slot uint32) string {
	return p.upvalueNames[slot]
}

func (p *proto) getConstant(idx uint32) string {
	return p.constants[idx]
}

// https://github.com/openresty/luajit2/blob/7952882d/src/lj_debug.c#L259
func (p *proto) getSlotName(pc, slot uint32) string {
restart:
	if pc == 0 || pc >= p.sizebc {
		return ""
	}
	name := p.getVarname(slot, pc)
	if name != "" {
		return name
	}
	// Walk the lua instructions backwards to find the name used to put the function in the slot
	pc--
	for ; pc > 0; pc-- {
		ins := p.bc[pc]
		op := bcOp(ins)
		ra := bcA(ins)
		if bcModeAIsBase(op) {
			if slot >= ra && (op != BC_KNIL || slot <= bcD(ins)) {
				return ""
			}
		} else if bcModeAIsDst(op) && ra == slot {
			switch op {
			case BC_MOV:
				if ra == slot {
					slot = bcD(ins)
					goto restart
				}
			case BC_GGET:
				return p.getConstant(bcD(ins))
			case BC_TGETS:
				method := p.getConstant(bcC(ins))
				table := p.getSlotName(pc, bcB(ins))
				if table != "" {
					return table + ":" + method
				}
				return method
			case BC_UGET:
				return p.getUpvalueName(bcD(ins))
			default:
				return ""
			}
		}
	}

	return ""
}

func (p *proto) getFunctionName(pc uint32) string {
	if p == nil {
		return "main"
	}
	if pc >= p.sizebc {
		// TODO: can we get a better pc for JIT frames?
		pc = 0
	}
	slot, metaname := getSlotOrMetaname(p.bc[pc])
	if metaname != "" {
		return metaname
	}
	return p.getSlotName(pc, slot)
}

// Parse a ULEB128 encoded number from a byte slice and return
// remaining bytes and the number.
//
//nolint:gocritic
func parseULEB128(b []byte) ([]byte, uint32) {
	v := uint32(b[0])
	b = b[1:]
	if v >= 0x80 {
		shift := 0
		v &= 0x7f
		for {
			shift += 7
			v |= uint32(b[0]&0x7f) << shift
			b = b[1:]
			if b[0] < 0x80 {
				break
			}
		}
	}
	return b, v
}

//nolint:gocritic
func parseString(b []byte) ([]byte, string) {
	for i, c := range b {
		if c == 0 {
			// FIXME: allocation
			return b[i:], string(b[:i])
		}
	}
	panic("no null terminator")
}

var varnames = []string{
	"(for index)",
	"(for limit)",
	"(for step)",
	"(for generator)",
	"(for state)",
	"(for control)"}

func parseVarinfo(b []byte, pc, slot uint32) string {
	var lastpc uint32
	for {
		var name string
		vn := int(b[0])
		if vn <= len(varnames) {
			if vn == 0 {
				break
			}
		} else {
			b, name = parseString(b)
		}
		b = b[1:]
		var pcdelta uint32
		b, pcdelta = parseULEB128(b)
		startpc := lastpc + pcdelta
		lastpc = startpc
		if startpc > pc {
			break
		}
		b, pcdelta = parseULEB128(b)
		endpc := startpc + pcdelta
		if pc < endpc && slot == 0 {
			if vn <= len(varnames) {
				return varnames[vn-1]
			}
			return name
		}
		slot--
	}
	return ""
}
