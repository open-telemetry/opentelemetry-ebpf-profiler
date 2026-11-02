// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestLoadBpfTraceLabelSections(t *testing.T) {
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
			tr := &Tracer{
				tracePool:      newTracePool(),
				origins:        &originRegistry{},
				processManager: &pm.ProcessManager{},
			}
			origin, err := tr.origins.Register(&samples.TypeMetadata{
				SampleTypes:  []samples.SampleType{{Type: "samples", Unit: "count"}},
				AppendValues: samples.AppendFirstContextValue,
			})
			require.NoError(t, err)
			header := support.Trace{
				Pid:              123,
				Origin:           origin,
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
			trace, err := tr.loadBpfTrace(raw)
			if tc.wantError {
				require.ErrorIs(t, err, errRecordUnexpectedSize)
				return
			}
			require.NoError(t, err)
			require.Equal(t, frames[:1], trace.KernelFrames)
			require.Equal(t, frames[1:], trace.FrameData)
			if tc.omitGoLabels {
				require.Empty(t, trace.CustomLabels)
			} else {
				require.Equal(t, map[libpf.String]libpf.String{
					libpf.Intern("tenant"): libpf.Intern("go"),
				}, trace.CustomLabels)
			}
			require.Equal(t, tc.wantDrop, tr.threadLabels.labelsNoDecoder.Load())
		})
	}
}

func TestThreadAndGoLabels(t *testing.T) {
	payload := []byte{0, 1, 'x'}
	padding := bytes.Repeat([]byte{0xff}, 5)
	goLabel := support.GolangLabel{}
	copy(goLabel.Key[:], "tenant")
	copy(goLabel.Val[:], "go")
	raw := append(append(pfunsafe.FromPointer(&goLabel), payload...), padding...)
	vd := variableDataDecoder{raw: raw}
	goLabelData, err := vd.decodeBytes(support.Sizeof_GolangLabel, "golang label")
	require.NoError(t, err)
	data, err := vd.decodeBytes(uint16(support.Sizeof_GolangLabel+len(payload)), "thread label")
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
