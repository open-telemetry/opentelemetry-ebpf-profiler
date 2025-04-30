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
	"path"
	"strings"
	"sync"
	"unsafe"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tpbase"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// #include "../../support/ebpf/types.h"
// #include "../../support/ebpf/luajit.h"
import "C"

const LuaJITFFIFunc = C.LUAJIT_FFI_FUNC

// Records all the "global" pointers we've seen.
type vmMap map[libpf.Address]struct{}

// Records all the JIT regions we've seen, value is SynchronizeMappings
// generation.
type regionMap map[process.Mapping]int

type regionKey struct {
	start, end uint64
}

type luajitData struct {
	// The distance from the "g" pointer in the GG_State struct to the start of the dispatch table.
	g2Dispatch uint16
	// The distance from the "g" pointer in the GG_State struct to the start of the trace array
	// in the jit_State struct.
	g2Traces uint16
	// Offset of cur_L field in the global_State struct.
	currentLOffset uint16
}

type luajitInstance struct {
	rm         remotememory.RemoteMemory
	protos     map[libpf.Address]*proto
	jitRegions regionMap
	pid        libpf.PID
	ebpf       interpreter.EbpfHandler
	// Map of g's we've seen, populated by the symbolizer goroutine and
	// consumed in SynchronizeMappings so needs to be protected by a mutex.
	mu  sync.Mutex
	vms vmMap

	// Currently mapped prefixes for each vms traces
	prefixesByG map[libpf.Address][]lpm.Prefix

	// Currently mapped prefixes for entire memory regions
	prefixes map[regionKey][]lpm.Prefix

	// Hash of the traces for each vm
	traceHashes map[libpf.Address]uint64
	cycle       int

	g2Traces uint16
}

var (
	_ interpreter.Data     = &luajitData{}
	_ interpreter.Instance = &luajitInstance{}
)

func (d *luajitData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	cdata := C.LuaJITProcInfo{
		g2dispatch:      C.u16(d.g2Dispatch),
		cur_L_offset:    C.u16(d.currentLOffset),
		cframe_size_jit: C.u16(cframeSizeJIT),
	}
	if err := ebpf.UpdateProcData(libpf.LuaJIT, pid, unsafe.Pointer(&cdata)); err != nil {
		return nil, err
	}

	return &luajitInstance{rm: rm,
		pid:         pid,
		ebpf:        ebpf,
		protos:      make(map[libpf.Address]*proto),
		jitRegions:  make(regionMap),
		prefixes:    make(map[regionKey][]lpm.Prefix),
		prefixesByG: make(map[libpf.Address][]lpm.Prefix),
		vms:         make(vmMap),
		traceHashes: make(map[libpf.Address]uint64),
		g2Traces:    d.g2Traces,
	}, nil
}

func (d *luajitData) Unload(_ interpreter.EbpfHandler) {}

func (l *luajitInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	// Clear memory ranges
	for _, prefixes := range l.prefixes {
		for _, prefix := range prefixes {
			_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		}
	}
	// Clear trace ranges
	for _, prefixes := range l.prefixesByG {
		for _, prefix := range prefixes {
			_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		}
	}
	return ebpf.DeleteProcData(libpf.LuaJIT, pid)
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	base := path.Base(info.FileName())
	if !strings.HasPrefix(base, "libluajit-5.1.so") &&
		base != "luajit" && base != "nginx" && base != "openresty" {
		return nil, nil
	}

	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	luaInterp, err := extractInterpreterBounds(info.Deltas(), cframeSize)
	if err != nil {
		return nil, err
	}
	logf("lj: interp range %v", luaInterp)

	ljd := &luajitData{}

	if err = extractOffsets(ef, ljd, luaInterp); err != nil {
		return nil, err
	}

	logf("lj: offsets %+v", ljd)

	if err = ebpf.UpdateInterpreterOffsets(support.ProgUnwindLuaJIT, info.FileID(),
		[]util.Range{luaInterp}); err != nil {
		return nil, err
	}

	return ljd, nil
}

// LuaJIT's interpreter isn't a function, its a raw chunk of assembly code with direct threaded
// jumps at end of each opcode. The public entrypoints (lua_pcall/lua_resume) call the lj_vm_pcall
// function at the end of this blob which set up the interpreter and starts executing.
// Even though its not a normal function an eh_frame entry is created for it, its really
// big and has a somewhat unique FDE we can pick out. We could tighten this up by looking for
// direct jumps to the start of the interpreter (one can be found lj_dispatch_update) but we'd
// still need to consult the stack deltas to get the end of the interpreter.
func extractInterpreterBounds(deltas sdtypes.StackDeltaArray, param int32) (util.Range,
	error) {
	for i := 0; i < len(deltas)-1; i++ {
		d, next := &deltas[i], &deltas[i+1]
		if next.Address-d.Address > 10_000 {
			// The first case covers x86 w/ dwarf and old versions of luajit ARM that used dwarf and
			// the second covers more recent arm versions that use frame pointers.
			if d.Info.Opcode == sdtypes.UnwindOpcodeBaseSP && d.Info.Param == param ||
				d.Info.Opcode == sdtypes.UnwindOpcodeBaseFP && d.Info.Param == 16 {
				return util.Range{Start: d.Address, End: next.Address}, nil
			}
		}
	}

	return util.Range{}, errors.New("failed to find interpreter range")
}

func (l *luajitInstance) getVMList() []libpf.Address {
	l.mu.Lock()
	defer l.mu.Unlock()
	gs := make([]libpf.Address, 0, len(l.vms))
	for g := range l.vms {
		gs = append(gs, g)
	}
	return gs
}

func (l *luajitInstance) addJITRegion(ebpf interpreter.EbpfHandler, pid libpf.PID,
	start, end uint64) error {
	prefixes, err := lpm.CalculatePrefixList(start, end)
	if err != nil {
		logf("lj: failed to calculate lpm: %v", err)
		return err
	}
	logf("lj: add JIT region pid(%v) %#x:%#x", pid, start, end)
	for _, prefix := range prefixes {
		// TODO: fix these: WARN[0267] Failed to lookup file ID 0x2a00000000
		fileID := uint64(C.LUAJIT_JIT_FILE_ID) << 32
		if err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindLuaJIT,
			host.FileID(fileID), 0); err != nil {
			return err
		}
	}
	k := regionKey{start: start, end: end}
	l.prefixes[k] = prefixes
	return nil
}

func (l *luajitInstance) addTrace(ebpf interpreter.EbpfHandler, pid libpf.PID, t trace, g,
	spadjust uint64) ([]lpm.Prefix, error) {
	start, end := t.mcode, t.mcode+uint64(t.szmcode)
	prefixes, err := lpm.CalculatePrefixList(start, end)
	if err != nil {
		logf("lj: failed to calculate lpm: %v", err)
		return nil, err
	}
	logf("lj: add trace mapping for pid(%v) %x:%x", pid, start, end)
	for _, prefix := range prefixes {
		fileID := uint64(C.LUAJIT_JIT_FILE_ID)<<32 | spadjust
		if err := ebpf.UpdatePidInterpreterMapping(pid, prefix, support.ProgUnwindLuaJIT,
			host.FileID(fileID), g); err != nil {
			return nil, err
		}
	}
	return prefixes, nil
}

func (l *luajitInstance) SynchronizeMappings(ebpf interpreter.EbpfHandler,
	_ reporter.SymbolReporter, pr process.Process, mappings []process.Mapping) error {
	return l.synchronizeMappings(ebpf, pr.PID(), mappings)
}

func (l *luajitInstance) synchronizeMappings(ebpf interpreter.EbpfHandler, pid libpf.PID,
	mappings []process.Mapping) error {
	cycle := l.cycle
	l.cycle++
	for i := range mappings {
		m := &mappings[i]
		if !m.IsAnonymous() || !m.IsExecutable() {
			continue
		}
		l.jitRegions[*m] = cycle
	}

	// Add new ones and remove garbage ones
	for m, c := range l.jitRegions {
		k := regionKey{start: m.Vaddr, end: m.Vaddr + m.Length}
		if c != cycle {
			for _, prefix := range l.prefixes[k] {
				if err := ebpf.DeletePidInterpreterMapping(pid, prefix); err != nil {
					return err
				}
			}
			delete(l.jitRegions, m)
			delete(l.prefixes, k)
		} else {
			if _, ok := l.prefixes[k]; !ok {
				if err := l.addJITRegion(ebpf, pid, m.Vaddr, m.Vaddr+m.Length); err != nil {
					return err
				}
			}
		}
	}

	return l.processVMs(ebpf, pid)
}

func (l *luajitInstance) processVMs(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	var badVMs []libpf.Address
	for _, g := range l.getVMList() {
		hash, traces, err := loadTraces(g+libpf.Address(l.g2Traces), l.rm)
		if err != nil {
			// if g is bad remove it
			log.Warnf("LuaJIT instance (%v) deleted: %v", g, err)
			badVMs = append(badVMs, g)
			continue
		}
		// Don't do anything if nothing changed.
		if hash == l.traceHashes[g] {
			continue
		}

		// We don't bother trying to keep things in sync, just delete them all and re-add them.
		prefixes := l.prefixesByG[g]
		l.prefixesByG[g] = nil
		for _, prefix := range prefixes {
			_ = ebpf.DeletePidInterpreterMapping(pid, prefix)
		}

		newPrefixes := []lpm.Prefix{}
	traceLoop:
		for i := range traces {
			t := traces[i]
			// Validate the trace
			foundRegion := false
			for reg := range l.jitRegions {
				if t.mcode >= reg.Vaddr && t.mcode < reg.Vaddr+reg.Length {
					foundRegion = true
					end := t.mcode + uint64(t.szmcode)
					if end > reg.Vaddr+reg.Length {
						log.Errorf("trace %v end goes beyond JIT region, bad szmcode", t)
						continue traceLoop
					}
					break
				}
			}

			if !foundRegion {
				log.Errorf("trace %v not in a JIT region", t)
				continue
			}

			stackDelta := uint64(t.spadjust) + uint64(cframeSizeJIT)
			// If this is a side trace, we need to add the spadjust of the root trace but
			// only if they are different.
			//https://github.com/openresty/luajit2/blob/7952882d/src/lj_gdbjit.c#L597
			if t.root != 0 && traces[t.root].spadjust != t.spadjust {
				stackDelta += uint64(traces[t.root].spadjust) + uint64(cframeSizeJIT)
			}
			p, err := l.addTrace(ebpf, pid, t, uint64(g), stackDelta)
			if err != nil {
				log.Errorf("Error adding trace(%d): %v", t.traceno, err)
				continue
			}
			newPrefixes = append(newPrefixes, p...)
		}

		log.Infof("LuaJIT traces for pid(%v) added: %d with %d prefixes and removed %d prefixes",
			pid, len(traces), len(newPrefixes), len(prefixes))

		l.prefixesByG[g] = newPrefixes
		l.traceHashes[g] = hash
	}
	l.removeVMs(badVMs)
	return nil
}

func (l *luajitInstance) removeVMs(gs []libpf.Address) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, g := range gs {
		delete(l.vms, g)
	}
}

func (l *luajitInstance) getGCproto(pt libpf.Address) (*proto, error) {
	if pt == 0 {
		return nil, nil
	}
	if gc, ok := l.protos[pt]; ok {
		return gc, nil
	}
	gc, err := newProto(l.rm, pt)
	if err != nil {
		return nil, err
	}
	l.protos[pt] = gc
	return gc, nil
}

// symbolizeFrame symbolizes the previous (up the stack)
func (l *luajitInstance) symbolizeFrame(symbolReporter reporter.SymbolReporter,
	funcName string, trace *libpf.Trace, ptAddr libpf.Address, pc uint32,
	frameID libpf.FrameID) error {
	var line uint32
	var fileName string
	if ptAddr != C.LUAJIT_FFI_FUNC {
		pt, err := l.getGCproto(ptAddr)
		if err != nil {
			return err
		}
		line = pt.getLine(pc)
		fileName = pt.getName()
	}
	logf("lj: [%x] %v+%v at %v:%v", ptAddr, funcName, pc, fileName, line)
	trace.AppendFrameID(libpf.LuaJITFrame, frameID)
	if !symbolReporter.FrameKnown(frameID) {
		symbolReporter.FrameMetadata(&reporter.FrameMetadataArgs{
			FrameID:        frameID,
			FunctionName:   funcName,
			SourceFile:     fileName,
			SourceLine:     libpf.SourceLineno(line),
			FunctionOffset: pc,
		})
	}
	return nil
}

func (l *luajitInstance) addVM(g libpf.Address) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	_, ok := l.vms[g]
	if !ok {
		l.vms[g] = struct{}{}
	}
	return !ok
}
func (l *luajitInstance) Symbolize(symbolReporter reporter.SymbolReporter, frame *host.Frame,
	trace *libpf.Trace) error {
	if !frame.Type.IsInterpType(libpf.LuaJIT) {
		return interpreter.ErrMismatchInterpreterType
	}

	if frame.File == 0 && frame.Lineno != 0 {
		// The BPF program will stash pointer to "G" when it sees a JIT frame w/o trace information
		// which may fail to unwind, we use it to see if the traces for this VM have changed. When
		// we reach a steady state where there's no new JIT activity this will always be 0.
		g := libpf.Address(frame.Lineno)
		if g != 0 {
			unseen := l.addVM(g)
			if unseen {
				log.Infof("New LuaJIT instance detected: %v", g)
				if l.ebpf.CoredumpTest() {
					return interpreter.ErrLJRestart
				}
			}
		}
		return nil
	}

	var funcName string
	if frame.File == C.LUAJIT_FFI_FUNC {
		switch frame.Lineno & 7 {
		case 0:
			funcName = "lua-frame"
		case 1:
			funcName = "c-frame"
		case 2:
			funcName = "cont-frame"
		case 3:
			return errors.New("unexpected frame type 3")
		case 4:
			funcName = "lua-pframe"
		case 5:
			funcName = "cpcall"
		case 6:
			funcName = "ff-pcall"
		case 7:
			funcName = "ff-pcall-hook"
		}
	} else {
		callerPT := libpf.Address(frame.Lineno)
		pt, err := l.getGCproto(callerPT)
		if err != nil {
			return err
		}
		funcName = pt.getFunctionName(frame.LJCallerPC)
	}

	calleePT := libpf.Address(frame.File)
	frameID := CreateFrameID(frame)
	if err := l.symbolizeFrame(symbolReporter, funcName, trace, calleePT,
		frame.LJCalleePC, frameID); err != nil {
		return err
	}

	return nil
}

func CreateFrameID(frame *host.Frame) libpf.FrameID {
	fileID := libpf.NewFileID(uint64(frame.File), uint64(frame.Lineno))
	lineno := uint64(frame.LJCalleePC)<<32 + uint64(frame.LJCallerPC)
	return libpf.NewFrameID(fileID, libpf.AddressOrLineno(lineno))
}

func (l *luajitInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	return nil, nil
}

func (l *luajitInstance) UpdateTSDInfo(interpreter.EbpfHandler, libpf.PID, tpbase.TSDInfo) error {
	return nil
}
