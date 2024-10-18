// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"encoding/binary"
	"sort"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
)

// createVDSOSyntheticRecordNone returns no synthesic deltas when the kernel vdso
// is known to have valid unwind information.
func createVDSOSyntheticRecordNone(_ *pfelf.File) sdtypes.IntervalData {
	return sdtypes.IntervalData{}
}

// createVDSOSyntheticRecordArm64 creates a generated stack-delta records for arm64 vdso.
// ARM64 kernel vDSO does not have proper `.eh_frame` section, so we synthesize it here.
// This assumes LR based unwinding for most of the vDSO. Additionally the following
// synthesization is done:
//   - if matching frame push/pop is found within a dynamic symbol, a frame pointer based
//     unwinding rule is added for that region
//   - the sigreturn helper is detected and signal unwind info is associated for it
func createVDSOSyntheticRecordArm64(ef *pfelf.File) sdtypes.IntervalData {
	deltas := sdtypes.StackDeltaArray{}
	deltas = append(deltas, sdtypes.StackDelta{Address: 0, Info: sdtypes.UnwindInfoLR})

	symbols, err := ef.ReadDynamicSymbols()
	if err != nil {
		return sdtypes.IntervalData{}
	}

	symbols.VisitAll(func(sym libpf.Symbol) {
		addr := uint64(sym.Address)
		if sym.Name == "__kernel_rt_sigreturn" {
			deltas = append(
				deltas,
				sdtypes.StackDelta{Address: addr, Info: sdtypes.UnwindInfoSignal},
				sdtypes.StackDelta{Address: addr + uint64(sym.Size), Info: sdtypes.UnwindInfoLR},
			)
			return
		}
		// Determine if LR is on stack
		code := make([]byte, sym.Size)
		if _, err = ef.ReadVirtualMemory(code, int64(sym.Address)); err != nil {
			return
		}
		var frameStart uint64
		for offs := uint64(0); offs < uint64(sym.Size); offs += 4 {
			switch binary.LittleEndian.Uint32(code[offs:]) {
			case 0xa9bf7bfd: // stp x29, x30, [sp, #-16]!
				frameStart = offs + 4
			case 0xa8c17bfd: // ldp x29, x30, [sp], #16
				if frameStart != 0 {
					deltas = append(
						deltas,
						sdtypes.StackDelta{
							Address: addr + frameStart,
							Info:    sdtypes.UnwindInfoFramePointer},
						sdtypes.StackDelta{
							Address: addr + offs + 4,
							Info:    sdtypes.UnwindInfoLR},
					)
				}
				frameStart = 0
			}
		}
	})
	sort.Slice(deltas, func(i, j int) bool {
		return deltas[i].Address < deltas[j].Address
	})

	return sdtypes.IntervalData{Deltas: deltas}
}
