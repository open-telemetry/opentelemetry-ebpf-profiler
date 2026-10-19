// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// TestLoadBpfTraceContextValueOrder checks that the agent rejects context
// values pushed after kernel frames, since eBPF does not check the ordering.
func TestLoadBpfTraceContextValueOrder(t *testing.T) {
	const contextValue, kernelFrame, userFrame = 42, 0x1234, 0x5678

	for _, tc := range []struct {
		name string
		data []uint64
		// Byte offsets of the end of the context values and kernel frames.
		contextEnd, kernelEnd uint16
		wantError             bool
	}{
		{name: "context values before kernel frames",
			data:       []uint64{contextValue, kernelFrame, userFrame},
			contextEnd: 8, kernelEnd: 16},
		{name: "context values after kernel frames",
			data:       []uint64{kernelFrame, contextValue, userFrame},
			contextEnd: 16, kernelEnd: 8, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Tracer{tracePool: newTracePool(), origins: &originRegistry{}}
			origin, err := tr.origins.Register(&samples.TypeMetadata{
				SampleTypes:  []samples.SampleType{{Type: "samples", Unit: "count"}},
				AppendValues: samples.AppendFirstContextValue,
			})
			require.NoError(t, err)

			end := uint16(8 * len(tc.data))
			header := support.Trace{
				Pid:               123,
				Origin:            origin,
				Context_value_end: tc.contextEnd,
				Kernel_frame_end:  tc.kernelEnd,
				Frame_data_end:    end,
				Thread_label_end:  end,
				Golang_label_end:  end,
				Variable_data_end: end,
				Num_frames:        1,
			}
			raw := append(pfunsafe.FromPointer(&header), pfunsafe.FromSlice(tc.data)...)

			trace, err := tr.loadBpfTrace(raw)
			if tc.wantError {
				require.ErrorIs(t, err, errRecordUnexpectedSize)
				require.ErrorContains(t, err, "kernel_frame end")
				return
			}
			require.NoError(t, err)
			require.Equal(t, []uint64{contextValue}, trace.ContextValues)
			require.Equal(t, []uint64{kernelFrame}, trace.KernelFrames)
			require.Equal(t, []uint64{userFrame}, trace.FrameData)
		})
	}
}
