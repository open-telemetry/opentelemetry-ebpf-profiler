// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package execinfomanager // import "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"

import (
	"debug/elf"

	aa "golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// regFP is the arm64 frame-pointer register (x29) number
const regFP = 29

// regLR is the arm64 link register (x30) number
const regLR = 30

// synthesizeIntervalData creates synthetic stack deltas if possible.
// Currently supported for ARM64 vDSO only.
func synthesizeIntervalData(ef *pfelf.File) *sdtypes.IntervalData {
	if ef.Machine == elf.EM_AARCH64 {
		soname, err := ef.DynString(elf.DT_SONAME)
		if err == nil && soname[0] == "linux-vdso.so.1" {
			return createVDSOSyntheticRecordArm64(ef)
		}
	}
	return &sdtypes.IntervalData{}
}

// createVDSOSyntheticRecordArm64 creates generated stack-delta records for ARM64 vDSO.
// ARM64 kernel vDSO does not have proper `.eh_frame` section, so we synthesize it here.
// This assumes LR based unwinding for most of the vDSO. Additionally the following
// synthetization is done:
//   - if matching STP/LDP is found within a dynamic symbol, an unwind rule with
//     is created and the frame size is extracted
//   - the sigreturn helper is detected and signal unwind info is associated for it
func createVDSOSyntheticRecordArm64(ef *pfelf.File) *sdtypes.IntervalData {
	intervals := &sdtypes.IntervalData{}
	firstAddress := ^uint64(0)
	_ = ef.VisitDynamicSymbols(func(sym libpf.Symbol) bool {
		if sym.Address == 0 || sym.Size == 0 {
			return true
		}
		if uint64(sym.Address) < firstAddress {
			firstAddress = uint64(sym.Address)
		}
		bb := sdtypes.BasicBlock{
			Start: uint64(sym.Address),
			End:   uint64(sym.Address) + sym.Size,
		}
		if sym.Name == "__kernel_rt_sigreturn" {
			bb.Deltas.Add(0, sdtypes.UnwindInfoSignal)
			intervals.Add(bb)
			return true
		}
		// Determine if LR is on stack
		code := make([]byte, sym.Size)
		if _, err := ef.ReadAt(code, int64(sym.Address)); err != nil {
			return true
		}

		var frameStart uint32
		var frameSize int
		bb.Deltas.Add(0, sdtypes.UnwindInfoLR)
		for offs := uint32(0); offs < uint32(sym.Size); offs += 4 {
			inst, err := aa.Decode(code[offs:])
			if err != nil {
				continue
			}
			switch inst.Op {
			case aa.RET:
				intervals.Add(bb)
				return true
			case aa.STP:
				if reg, ok := arm.Xreg2num(inst.Args[0]); !ok || reg != regFP {
					continue
				}
				if reg, ok := arm.Xreg2num(inst.Args[1]); !ok || reg != regLR {
					continue
				}
				imm, ok := arm.DecodeImmediate(inst.Args[2])
				if !ok {
					continue
				}
				imm = -imm
				if imm < 1024 {
					frameStart = offs + 4
					frameSize = int(imm)
				}
			case aa.LDP:
				if reg, ok := arm.Xreg2num(inst.Args[0]); !ok || reg != regFP {
					continue
				}
				if reg, ok := arm.Xreg2num(inst.Args[1]); !ok || reg != regLR {
					continue
				}
				if frameStart == 0 {
					return true
				}
				bb.Deltas.Add(frameStart, sdtypes.UnwindInfo{
					BaseReg:    support.UnwindRegFp,
					Param:      int32(frameSize),
					AuxBaseReg: support.UnwindRegFp,
					AuxParam:   8,
				})
				bb.Deltas.Add(offs+4, sdtypes.UnwindInfoLR)
				frameStart = 0
			}
		}
		return true
	})
	bb := sdtypes.BasicBlock{
		Start: 0,
		End:   firstAddress,
	}
	bb.Deltas.Add(0, sdtypes.UnwindInfoLR)
	intervals.Add(bb)
	intervals.Sort()

	return intervals
}
