// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build luajit_offsets_test

// Test-only rexports for luajit internals.
// Used by tools/luajitoffsets

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import "go.opentelemetry.io/ebpf-profiler/libpf"

type (
	LuajitData = luajitData
	OffsetData = offsetData
	Trace      = trace
	ProtoRaw   = protoRaw
)

const (
	LJCFJitUtilTraceinfoSym = ljCFJitUtilTraceinfoSym
	TracePartOffset         = tracePartOffset
)

var (
	ExtractInterpreterBounds = extractInterpreterBounds
	NewLuajitData            = newLuajitData
	NewOffsetData            = newOffsetData
)

func (d *luajitData) G2Dispatch() uint16 { return d.g2Dispatch }

func (d *luajitData) G2Traces() uint16 { return d.g2Traces }

func (d *luajitData) CurrentLOffset() uint16 { return d.currentLOffset }

func (o *offsetData) FoundSymbols() map[libpf.SymbolName]libpf.Symbol { return o.foundSymbols }

func (o *offsetData) FindTraceInfoFromLuaOpen() (*libpf.Symbol, error) {
	return o.findTraceInfoFromLuaOpen()
}

func (o *offsetData) FindLjDispatchUpdateAddr() (libpf.Address, error) {
	return o.e.findLjDispatchUpdateAddr(o.luajitOpen, o.luajitOpenAddr)
}
