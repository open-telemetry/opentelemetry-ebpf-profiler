// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package execinfomanager // import "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/stretchr/testify/require"
)

func TestVDSOArm64(t *testing.T) {
	frameSize16 := sdtypes.UnwindInfo{
		BaseReg:    support.UnwindRegFp,
		Param:      16,
		AuxBaseReg: support.UnwindRegFp,
		AuxParam:   8,
	}

	testCases := map[string]sdtypes.IntervalData{
		"vdso.arch64.withframe": {
			NumDeltas: 9,

			Blocks: []*sdtypes.BasicBlock{
				{
					Start: 0,
					End:   0x7d0,
					Deltas: sdtypes.StackDeltaArray{
						{0, sdtypes.UnwindInfoLR},
					},
				},
				{
					Start: 0x7d0,
					End:   0x7d0 + 40,
					Deltas: sdtypes.StackDeltaArray{
						{0, sdtypes.UnwindInfoLR},
						{8, frameSize16},
						{20, sdtypes.UnwindInfoLR},
					},
				},
				{
					Start: 0x7f8,
					End:   0x7f8 + 40,
					Deltas: sdtypes.StackDeltaArray{
						{0, sdtypes.UnwindInfoLR},
						{8, frameSize16},
						{20, sdtypes.UnwindInfoLR},
					},
				},
				{
					Start: 0x820,
					End:   0x820 + 172,
					Deltas: sdtypes.StackDeltaArray{
						{0, sdtypes.UnwindInfoLR},
					},
				},
				{
					Start: 0x8f8,
					End:   0x8f8 + 8,
					Deltas: sdtypes.StackDeltaArray{
						{0, sdtypes.UnwindInfoSignal},
					},
				},
			},
		},
	}

	for name, expected := range testCases {
		t.Run(name, func(t *testing.T) {
			ef, err := pfelf.Open("testdata/" + name)
			require.NoError(t, err)
			defer ef.Close()

			intervals := createVDSOSyntheticRecordArm64(ef)
			require.Equal(t, expected, *intervals, "vdso deltas wrong")
		})
	}
}
