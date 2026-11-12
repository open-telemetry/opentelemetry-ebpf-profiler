// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// newTestDecodePM returns a process manager for decode tests and its
// registered sampling origin ID.
func newTestDecodePM(t *testing.T) (*ProcessManager, uint16) {
	t.Helper()
	pmv, err := New(t.Context(), Config{
		InterpretersConfig:    interpreterconfig.NoInterpreters(),
		MonitorInterval:       time.Hour,
		ExecutableUnloadDelay: time.Hour,
		EbpfHandler:           &testEbpfHandler{},
		IncludeEnvVars:        libpf.Set[string]{},
	})
	require.NoError(t, err)
	originID, err := pmv.origins.Register(&OriginEntry{
		Meta: &samples.TypeMetadata{
			SampleTypes:  []samples.SampleType{{Type: "samples", Unit: "count"}},
			AppendValues: samples.AppendFirstContextValue,
		},
	})
	require.NoError(t, err)
	t.Cleanup(pmv.Close)
	return pmv, originID
}

// decodeRecord copies a raw trace record into a pooled trace event and
// decodes it, mirroring HandleTrace.
func (pm *ProcessManager) decodeRecord(t *testing.T, raw []byte) *traceEvent {
	t.Helper()
	e := pm.tracePool.Get().(*traceEvent)
	*e = traceEvent{}
	e.recordLen = copy(e.rawBytes(), raw)
	require.NoError(t, validateRecord(e.rawBytes()[:e.recordLen]))
	require.NoError(t, pm.decodeTrace(e))
	return e
}

// TestDecodeTraceContextValueOrder checks that context values pushed after
// kernel frames are rejected.
func TestDecodeTraceContextValueOrder(t *testing.T) {
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
			pmv, originID := newTestDecodePM(t)

			end := uint16(8 * len(tc.data))
			header := support.Trace{
				Pid:               123,
				Origin:            originID,
				Context_value_end: tc.contextEnd,
				Kernel_frame_end:  tc.kernelEnd,
				Frame_data_end:    end,
				Thread_label_end:  end,
				Golang_label_end:  end,
				Variable_data_end: end,
				Num_frames:        1,
			}
			raw := append(pfunsafe.FromPointer(&header), pfunsafe.FromSlice(tc.data)...)

			if tc.wantError {
				err := validateRecord(raw)
				require.ErrorIs(t, err, ErrRecordUnexpectedSize)
				require.ErrorContains(t, err, "kernel_frame end")
				return
			}

			trace := pmv.decodeRecord(t, raw)
			require.Equal(t, []uint64{contextValue}, trace.ContextValues)
			require.Equal(t, []uint64{kernelFrame}, trace.KernelFrames)
			require.Equal(t, []uint64{userFrame}, trace.FrameData)
		})
	}
}

func TestDecodeTraceLabelSections(t *testing.T) {
	for _, tc := range []struct {
		name          string
		threadPayload []byte
		threadEnd     uint16
		omitGoLabels  bool
		wantError     bool
		wantDrop      int64
	}{
		{name: "missing schema preserves Go labels",
			threadPayload: []byte{0, 1, 'x'}, threadEnd: 83, wantDrop: 1},
		{name: "absent thread section"},
		{name: "empty thread section", threadEnd: 80},
		{name: "absent Go section",
			threadPayload: []byte{0, 1, 'x'}, threadEnd: 19, omitGoLabels: true, wantDrop: 1},
		{name: "overlapping thread section", threadEnd: 79, wantError: true},
		{name: "thread section beyond record", threadEnd: 81, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pmv, _ := newTestDecodePM(t)

			header := support.Trace{
				Pid:              123,
				Origin:           1,
				Kernel_frame_end: 8,
				Frame_data_end:   16,
				Thread_label_end: tc.threadEnd,
				Num_frames:       1,
			}
			frames := []uint64{0x1234, 0x5678}
			data := append([]byte(nil), pfunsafe.FromSlice(frames)...)
			if !tc.omitGoLabels {
				label := support.GolangLabel{}
				copy(label.Key[:], "tenant")
				copy(label.Val[:], "go")
				data = append(data, pfunsafe.FromPointer(&label)...)
				header.Golang_label_end = uint16(len(data))
			}
			if tc.threadPayload != nil {
				data = append(data, tc.threadPayload...)
				// Padding is not part of the payload and need not be zeroed.
				data = append(data, bytes.Repeat([]byte{0xff}, (-len(data))&7)...)
			}
			header.Variable_data_end = uint16(len(data))
			raw := append(pfunsafe.FromPointer(&header), data...)

			if tc.wantError {
				err := validateRecord(raw)
				require.ErrorIs(t, err, ErrRecordUnexpectedSize)
				return
			}

			trace := pmv.decodeRecord(t, raw)
			require.Equal(t, frames[:1], trace.KernelFrames)
			require.Equal(t, frames[1:], trace.FrameData)
			if tc.omitGoLabels {
				require.Empty(t, trace.CustomLabels)
			} else {
				require.Equal(t, map[libpf.String]libpf.String{
					libpf.Intern("tenant"): libpf.Intern("go"),
				}, trace.CustomLabels)
			}
			require.Equal(t, tc.wantDrop, pmv.threadLabels.labelsNoDecoder.Load())
		})
	}
}

func TestDecodeThreadAndGoLabels(t *testing.T) {
	payload := []byte{0, 1, 'x'}
	padding := bytes.Repeat([]byte{0xff}, 5)
	goLabel := support.GolangLabel{}
	copy(goLabel.Key[:], "tenant")
	copy(goLabel.Val[:], "go")
	raw := append(append(pfunsafe.FromPointer(&goLabel), payload...), padding...)
	vd := variableDataDecoder{raw: raw}
	goLabelData, err := vd.bytes(support.Sizeof_GolangLabel, "golang label")
	require.NoError(t, err)
	data, err := vd.bytes(uint16(support.Sizeof_GolangLabel+len(payload)), "thread label")
	require.NoError(t, err)
	require.Equal(t, payload, data)
	require.Equal(t, len(data), cap(data))

	labels := libpf.ThreadLabels{
		libpf.Intern("tenant"): libpf.Intern("thread"),
		libpf.Intern("route"):  libpf.Intern("/orders"),
	}
	var validator customLabelValidator
	labels = validator.decode(goLabelData, labels)
	require.Equal(t, libpf.ThreadLabels{
		libpf.Intern("tenant"): libpf.Intern("go"),
		libpf.Intern("route"):  libpf.Intern("/orders"),
	}, labels)
}

func TestValidateRecord(t *testing.T) {
	// A record shorter than the trace header is rejected.
	require.ErrorIs(t, validateRecord(make([]byte, support.Sizeof_TraceHeader-1)),
		ErrRecordTooSmall)

	// A header-only record with all sections absent is valid.
	header := support.Trace{Pid: 123, Origin: 1}
	require.NoError(t, validateRecord(pfunsafe.FromPointer(&header)))

	// A record promising more variable data than it holds is rejected.
	header.Variable_data_end = 8
	require.ErrorIs(t, validateRecord(pfunsafe.FromPointer(&header)),
		ErrRecordUnexpectedSize)

	// A record claiming a variable data region beyond what the eBPF side can
	// produce is rejected.
	header.Variable_data_end = support.Sizeof_TraceWithData - support.Sizeof_TraceHeader + 1
	require.ErrorIs(t, validateRecord(pfunsafe.FromPointer(&header)),
		ErrRecordUnexpectedSize)

	// The uint64-valued sections must end on 8-byte boundaries.
	header = support.Trace{Origin: 1, Kernel_frame_end: 5}
	require.ErrorIs(t, validateRecord(pfunsafe.FromPointer(&header)),
		ErrRecordUnexpectedSize)
}
