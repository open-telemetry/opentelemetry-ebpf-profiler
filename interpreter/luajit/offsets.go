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
	"debug/elf"
	"fmt"
	"slices"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// This is the main "global" struct in luajit.
//
//	type = struct GG_State {
//	    lua_State L;
//	    global_State g;
//	    jit_State J;
//	    HotCount hotcount[64];
//	    ASMFunction dispatch[243];
//	    BCIns bcff[57];
//	}
//
// All the code here is to enable us navigate around it.  We need:
//
// 1. The distance from g to dispatch
// 2. The distance from g to J.trace
// 3. The offset of cur_L in global_State
//
// Some versions of openresty have a stripped luajit which makes things a little more
// complicated because we have to start from a public symbol and work our way around.
func extractOffsets(ef *pfelf.File, ljd *luajitData, ir util.Range) error {
	oft := offsetData{}
	if err := oft.init(ef); err != nil {
		return err
	}

	curLOffset, err := oft.findCurLOffset()
	if err != nil {
		return err
	}
	if curLOffset > 0x7fff {
		return fmt.Errorf("lj: curL offset %v is too large", curLOffset)
	}
	ljd.currentLOffset = curLOffset

	g2Traces, err := oft.findG2TracesOffset()
	if err != nil {
		return fmt.Errorf("lj: failed to find g2traces offset: %v", err)
	}
	if g2Traces > 0xffff {
		return fmt.Errorf("lj: g to traces offset %v is too large", g2Traces)
	}
	ljd.g2Traces = uint16(g2Traces)

	g2dispatch, err := oft.findG2DispatchOffset()
	if err != nil {
		return err
	}
	if g2dispatch > 0xffff {
		return fmt.Errorf("lj: dispatch_L offset %v is too large", g2dispatch)
	}
	ljd.g2Dispatch = uint16(g2dispatch)

	// If we have symbols we can check that the start address is correct.
	if s, e := oft.lookupSymbol("lj_vm_asm_begin"); e == nil && ir.Start != uint64(s.Address) {
		return fmt.Errorf("lj: unexpected start address %x, expected %x", s.Address, ir.Start)
	}

	return nil
}

type extractor interface {
	// LUA_API void lua_close(lua_State *L)
	// {
	//	  global_State *g = G(L);
	//	  int i;
	//	  L = mainthread(g);  /* Only the main thread can be closed. */
	//
	// #if LJ_HASPROFILE
	//	luaJIT_profile_stop(L);
	// #endif
	//
	//	setgcrefnull(g->cur_L);   <---- DING DING DING
	findOffsetsFromLuaClose(b []byte) (uint64, uint64, error)

	// Find call to lj_dispatch_update in luaopen_jit by looking for
	// first call being passed G loaded from L->glref.
	findLjDispatchUpdateAddr(b []byte, addr uint64) (uint64, error)

	// luaopen_jit calls jit_init which calls lj_dispatch_update. lj_dispatch_update
	// has this line near the beginning:
	//   ASMFunction *disp = G2GG(g)->dispatch;
	// Use this line to find the g2dispatch offset.
	findG2DispatchOffsetFromLjDispatchUpdate(b []byte) (uint64, error)

	// jit_checktrace does this:
	//
	//  jit_State *J = L2J(L);
	//   if (tr > 0 && tr < J->sizetrace)
	//   return traceref(J, tr);
	//
	// L2J will find J relative to G and traceref will find traces
	// relative to J so we find both offsets and add them to get
	// g2traces offset.
	findG2TracesOffsetFromChecktrace([]byte) (uint64, error)

	// Return true if the code in b calls targetCall.
	callExists(b []byte, baseAddr, targetCall int64) (bool, error)

	findFirstCall(b []byte, baseAddr int64) (uint64, error)

	find3rdArgToLibPreregCall(b []byte, baseAddr int64) (uint64, error)

	find4thArgToLibRegCall(b []byte, baseAddr int64) (int64, error)
}

func newExtractor(ef *pfelf.File) extractor {
	switch ef.Machine {
	case elf.EM_X86_64:
		return &x86Extractor{ef: ef}
	case elf.EM_AARCH64:
		return &armExtractor{ef: ef}
	default:
		panic("unexpected architecture")
	}
}

type offsetData struct {
	f              *pfelf.File
	syms, dsyms    *libpf.SymbolMap
	luajitOpen     []byte
	luajitOpenAddr uint64
	e              extractor
}

func (o *offsetData) init(ef *pfelf.File) error {
	o.f = ef
	o.e = newExtractor(ef)
	o.syms, _ = ef.ReadSymbols()
	o.dsyms, _ = ef.ReadDynamicSymbols()
	//nolint: misspell
	// Two analyses use luaopen_jit so cache it.
	b, addr, err := o.readSymByName("luaopen_jit")
	if err != nil {
		return err
	}
	o.luajitOpen = b
	o.luajitOpenAddr = uint64(addr)
	return nil
}

func (o *offsetData) findCurLOffset() (uint16, error) {
	b, _, err := o.readSymByName("lua_close")
	if err != nil {
		return 0, err
	}
	glref, curL, err := o.e.findOffsetsFromLuaClose(b)
	if err != nil {
		return 0, err
	}

	// openresty 1.15 was compiled w/o LJ_GC64 which we don't support.
	if glref != 0x10 {
		//nolint: lll
		return 0, fmt.Errorf("unexpected glref offset %x, only luajit with LJ_GC64 is supported", glref)
	}
	return uint16(curL), nil
}

func (o *offsetData) findG2DispatchOffset() (uint64, error) {
	luaDispatchUpdateAddr, err := o.e.findLjDispatchUpdateAddr(o.luajitOpen, o.luajitOpenAddr)
	if err != nil {
		return 0, err
	}
	b := make([]byte, 300)
	_, err = o.f.ReadAt(b, int64(luaDispatchUpdateAddr))
	if err != nil {
		return 0, err
	}
	return o.e.findG2DispatchOffsetFromLjDispatchUpdate(b)
}

func (o *offsetData) findG2TracesOffset() (uint64, error) {
	if sym, err := o.lookupSymbol("jit_checktrace"); err == nil {
		// easiest case
		b, err := o.readSym(sym)
		if err != nil {
			return 0, err
		}
		return o.e.findG2TracesOffsetFromChecktrace(b)
	}

	// jit_checktrace could be inlined or we could be dealing with a stripped binary
	if sym, err := o.lookupSymbol("lj_cf_jit_util_traceinfo"); err == nil {
		// Inline case
		b, er := o.readSym(sym)
		if er != nil {
			return 0, er
		}
		return o.e.findG2TracesOffsetFromChecktrace(b)
	}

	// Binary must be stripped, find traceinfo the hard way.
	sym, err := o.findTraceInfoFromLuaOpen()
	if err != nil {
		return 0, err
	}

	b, err := o.readSym(sym)
	if err != nil {
		return 0, err
	}

	// jit_checktrace will be first call in lj_cf_jit_util_traceinfo or it will be inlined,
	// first try the inline approach by running find on a small subset of the instructions.
	if len(b) > 200 {
		b = b[:200]
	}

	addr, err := o.e.findG2TracesOffsetFromChecktrace(b)
	if err != nil {
		callAddr, err := o.e.findFirstCall(b, int64(sym.Address))
		if err != nil {
			return 0, err
		}
		b := make([]byte, 100)
		_, err = o.f.ReadAt(b, int64(callAddr))
		if err != nil {
			return 0, err
		}
		addr, err = o.e.findG2TracesOffsetFromChecktrace(b)
		if err != nil {
			return 0, err
		}
	}

	return addr, nil
}

// Get address of lj_cf_jit_util_traceinfo by looking at the lj_lib_prereg call in luaopen_jit:
// https://github.com/openresty/luajit2/blob/7952882d/src/lib_jit.c#L803
// The lj_lib_prereg call may or may not be inlined which we can detect by looking for a call to the
// public lua_pushcclosure method. In either case we need to get the address of "luaopen_jit_util"
// which will be an argument to lj_lib_prereg, or lj_pushclosure.
// Then we can read that function to find the address of the function array "lj_lib_cf_jit_util"
// which will be an argument to lj_lib_register.  Finally the lj_cf_jit_util_traceinfo function
// will be the 4th element of that array.
func (o *offsetData) findTraceInfoFromLuaOpen() (*libpf.Symbol, error) {
	pushCClosure, err := o.lookupSymbol("lua_pushcclosure")
	if err != nil {
		return nil, err
	}
	pushClosureAddr := int64(pushCClosure.Address)
	baseAddr := int64(o.luajitOpenAddr)
	var luaopenJitUtilAddr uint64
	inlined, err := o.e.callExists(o.luajitOpen, baseAddr, pushClosureAddr)
	if err != nil {
		return nil, err
	}

	if inlined {
		luaopenJitUtilAddr, err = findRipRelativeLea2ndArgTo2ndCall(o.luajitOpen, baseAddr,
			pushClosureAddr)
		if err != nil {
			return nil, err
		}
	} else {
		luaopenJitUtilAddr, err = o.e.find3rdArgToLibPreregCall(o.luajitOpen, baseAddr)
		if err != nil {
			return nil, err
		}
	}
	logf("lj: luaopen_jit_util address %x", luaopenJitUtilAddr)
	// luaopen_jit_util is tiny:
	// https://github.com/openresty/luajit2/blob/7952882d9c/src/lib_jit.c#L484
	b := make([]byte, 100)
	_, err = o.f.ReadAt(b, int64(luaopenJitUtilAddr))
	if err != nil {
		return nil, err
	}
	libJitFunctionAddresses, err := o.e.find4thArgToLibRegCall(b, int64(luaopenJitUtilAddr))
	if err != nil {
		return nil, err
	}

	// libJitFunctionAddresses should be this static array:
	// No permalinks for generated code, its in lj_libdef.h
	// static const lua_CFunction lj_lib_cf_jit_util[] = {
	// 	lj_cf_jit_util_funcinfo,
	// 	lj_cf_jit_util_funcbc,
	// 	lj_cf_jit_util_funck,
	// 	lj_cf_jit_util_funcuvname,
	// 	lj_cf_jit_util_traceinfo,
	// 	lj_cf_jit_util_traceir,
	// 	lj_cf_jit_util_tracek,
	// 	lj_cf_jit_util_tracesnap,
	// 	lj_cf_jit_util_tracemc,
	// 	lj_cf_jit_util_traceexitstub,
	// 	lj_cf_jit_util_ircalladdr
	//   };
	const traceInfoIndex = 4
	funcAddrs := make([]uint64, 12)
	_, err = o.f.ReadAt(libpf.SliceFrom(funcAddrs), libJitFunctionAddresses)
	if err != nil {
		return nil, err
	}

	traceInfoAddr := funcAddrs[traceInfoIndex]

	// Derive size by sorting and seeing offset to next function, swag if its last (it won't be).
	slices.Sort(funcAddrs)

	// Its a tiny function, give it reasonable default.
	traceInfoSize := 100
	for i, addr := range funcAddrs {
		if addr == traceInfoAddr && i != len(funcAddrs)-1 {
			traceInfoSize = int(funcAddrs[i+1] - funcAddrs[i])
			break
		}
	}

	return &libpf.Symbol{
		Name:    "lj_cf_jit_util_traceinfo",
		Address: libpf.SymbolValue(traceInfoAddr),
		Size:    traceInfoSize}, nil
}

func (o *offsetData) readSym(sym *libpf.Symbol) ([]byte, error) {
	b := make([]byte, sym.Size)
	n, err := o.f.ReadAt(b, int64(sym.Address))
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("failed to read %s fully", sym.Name)
	}
	return b, nil
}

func (o *offsetData) lookupSymbol(name libpf.SymbolName) (s *libpf.Symbol, err error) {
	s, err = o.f.LookupSymbol(name)
	if err == pfelf.ErrSymbolNotFound && o.syms != nil {
		s, err = o.syms.LookupSymbol(name)
	}
	if s == nil && o.dsyms != nil {
		s, err = o.dsyms.LookupSymbol(name)
	}
	return s, err
}

//nolint:gocritic
func (o *offsetData) readSymByName(name string) ([]byte, int64, error) {
	sym, err := o.lookupSymbol(libpf.SymbolName(name))
	if err != nil {
		return nil, 0, err
	}
	b := make([]byte, sym.Size)
	_, err = o.f.ReadAt(b, int64(sym.Address))
	if err != nil {
		return nil, 0, err
	}
	return b, int64(sym.Address), nil
}
