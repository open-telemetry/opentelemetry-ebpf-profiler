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
	"encoding/binary"
	"errors"
	"hash/fnv"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// This offset is the same in arm64/x86_64 for all known versions of luajit.
// (gdb) p &((GCtrace*)0)->startins
// $7 = (uint16_t *) 0x50
const tracePartOffset = 0x50

// Definition:
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_jit.h#L423
type jitStatePart struct {
	trace     libpf.Address
	_         uint32 // freetrace
	sizetrace uint32
}

// Definition:
// https://github.com/openresty/luajit2/blob/7952882d/src/lj_jit.h#L259
type trace struct {
	_       uint32 /* startins Original bytecode of starting instruction. */
	szmcode uint32 /* Size of machine code. */
	mcode   uint64 /* Start of machine code. */
	_       uint32 /* mcloop */
	// For arm is LJ_ABI_PAUTH defined?
	// For docker images at least LJ_ABI_PAUTH is not defined.
	// ASMFunction mcauth;	/* Start of machine code, with ptr auth applied. */
	_        uint16 /* Number of child traces (root trace only). */
	spadjust uint16 /* Stack pointer adjustment (offset in bytes). */
	traceno  uint16 /* Trace number. */
	_        uint16 /* Linked trace (or self for loops). */
	root     uint16 /* Root trace of side trace (or 0 for root traces). */
}

// key == traceId
type traceMap map[uint16]trace

func getAndHashTraceAddrs(tracesAddr libpf.Address, rm remotememory.RemoteMemory) (
	hash uint64, sizetrace int, traceAddrs []libpf.Address, err error) {
	j := jitStatePart{}
	if err := rm.Read(tracesAddr, libpf.SliceFrom(&j)); err != nil {
		return 0, 0, nil, err
	}
	traceAddrs = []libpf.Address{}
	b := make([]byte, 8)
	h := fnv.New64()
	binary.LittleEndian.PutUint32(b, j.sizetrace)
	h.Write(b[:4])
	addrs := make([]libpf.Address, j.sizetrace)
	if err := rm.Read(j.trace, libpf.SliceFrom(addrs)); err != nil {
		return 0, 0, nil, err
	}
	for _, addr := range addrs {
		if addr == 0 {
			continue
		}
		binary.LittleEndian.PutUint64(b, uint64(addr))
		h.Write(b)
		traceAddrs = append(traceAddrs, addr)
	}
	return h.Sum64(), int(j.sizetrace), traceAddrs, nil
}

func loadTraces(tracesAddr libpf.Address, rm remotememory.RemoteMemory) (uint64, traceMap, error) {
	h, sztrace, traceAddrs, err := getAndHashTraceAddrs(tracesAddr, rm)
	if err != nil {
		return 0, nil, err
	}
	traces := traceMap{}
	for _, addr := range traceAddrs {
		t := trace{}
		if err := rm.Read(addr+tracePartOffset, libpf.SliceFrom(&t)); err != nil {
			return 0, nil, err
		}
		if t.traceno > uint16(sztrace) {
			return 0, nil, errors.New("invalid traceno")
		}
		traces[t.traceno] = t
	}
	return h, traces, nil
}
