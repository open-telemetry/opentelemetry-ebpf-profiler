// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Boilerplate stubs for LuaJIT implementation.

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import (
	"debug/elf"
	"errors"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/util"
)

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
	interpreter.InstanceStubs
}

var (
	_ interpreter.Data     = &luajitData{}
	_ interpreter.Instance = &luajitInstance{}
)

func (d *luajitData) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	return &luajitInstance{}, nil
}

func (d *luajitData) Unload(_ interpreter.EbpfHandler) {}

func (l *luajitInstance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return nil
}

func GetLoader(_ Config) interpreter.Loader {
	return loader
}

func loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	return nil, nil
}

const (
	// minInterpreterSize is the lower bound for the size of the stack delta
	// corresponding to the interpreter.
	minInterpreterSize = 10_000
)

// LuaJIT's interpreter isn't a function, it's a raw chunk of assembly code with direct threaded
// jumps at end of each opcode. The public entrypoints (lua_pcall/lua_resume) call the lj_vm_pcall
// function at the end of this blob which set up the interpreter and starts executing.
// Even though it's not a normal function an eh_frame entry is created for it, it's really
// big and has a somewhat unique FDE we can pick out. We could tighten this up by looking for
// direct jumps to the start of the interpreter (one can be found lj_dispatch_update) but we'd
// still need to consult the stack deltas to get the end of the interpreter.
func extractInterpreterBounds(machine elf.Machine, intervals sdtypes.IntervalData, param int32) (util.Range,
	error) {
DeltasLoop:
	for i, bk := range intervals.Blocks {
		for j, d := range bk.Deltas {
			var next *sdtypes.StackDelta
			var nextBk *sdtypes.BasicBlock
			if j < len(bk.Deltas)-1 {
				next = &bk.Deltas[j+1]
				nextBk = bk
			} else {
				for nextI := i + 1; nextI < len(intervals.Blocks); nextI += 1 {
					nextBk = intervals.Blocks[nextI]
					if len(nextBk.Deltas) != 0 {
						next = &nextBk.Deltas[0]
						break
					}
				}
			}
			if next == nil {
				break DeltasLoop
			}
			dAddr := bk.Start + uint64(d.Offset)
			nextAddr := nextBk.Start + uint64(next.Offset)
			if nextAddr < dAddr || nextAddr-dAddr <= minInterpreterSize {
				continue
			}

			// The first case covers x86 w/ dwarf and old versions of luajit ARM that used dwarf and
			// the second covers more recent arm versions that use frame pointers.
			if (d.Info.BaseReg == support.UnwindRegSp && d.Info.Param == param) ||
				(machine == elf.EM_AARCH64 && d.Info.BaseReg == support.UnwindRegFp && d.Info.Param == 16) {
				return util.Range{Start: dAddr, End: nextAddr}, nil
			}
		}
	}
	return util.Range{}, errors.New("failed to find interpreter range")
}
