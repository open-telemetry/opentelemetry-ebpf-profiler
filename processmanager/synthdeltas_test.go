// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"

	"github.com/stretchr/testify/require"
)

func TestVDSOArm64(t *testing.T) {
	testCases := map[string]sdtypes.StackDeltaArray{
		"vdso.arch64.withframe": {
			{Address: 0, Info: sdtypes.UnwindInfoLR},
			{Address: 0x7d8, Info: sdtypes.UnwindInfoFramePointer},
			{Address: 0x7e4, Info: sdtypes.UnwindInfoLR},
			{Address: 0x800, Info: sdtypes.UnwindInfoFramePointer},
			{Address: 0x80c, Info: sdtypes.UnwindInfoLR},
			{Address: 0x8f8, Info: sdtypes.UnwindInfoSignal},
			{Address: 0x900, Info: sdtypes.UnwindInfoLR},
		},
	}

	for name, expected := range testCases {
		t.Run(name, func(t *testing.T) {
			ef, err := pfelf.Open("testdata/" + name)
			require.NoError(t, err)
			defer ef.Close()

			deltas := createVDSOSyntheticRecordArm64(ef)
			require.Equal(t, expected, deltas.Deltas, "vdso deltas wrong")
		})
	}
}
