// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestLoadBpfTraceLabelSections(t *testing.T) {
	for _, tc := range []struct {
		name          string
		goLabels      bool
		threadPayload []byte
		// Overrides the Thread_label_end matching the data actually written.
		threadEnd uint16
		goEnd     uint16
		wantError bool
		wantDrop  int64
	}{
		{name: "no labels"},
		{name: "Go labels only", goLabels: true},
		{name: "thread labels only without schema", threadPayload: []byte{0, 1, 'x'}, wantDrop: 1},
		{name: "both sections without schema", goLabels: true,
			threadPayload: []byte{0, 1, 'x'}, wantDrop: 1},
		{name: "aligned payload", goLabels: true,
			threadPayload: []byte{0, 6, 'a', 'b', 'c', 'd', 'e', 'f'}, wantDrop: 1},
		{name: "empty thread section", goLabels: true, threadEnd: 16},
		{name: "overlapping thread section", threadEnd: 15, wantError: true},
		{name: "thread section beyond record", threadEnd: 17, wantError: true},
		{name: "Go section starts in thread padding", goLabels: true,
			threadPayload: []byte{0, 1, 'x'}, goEnd: 23, wantError: true},
		{name: "Go section beyond record", goLabels: true, goEnd: 81, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &Tracer{
				tracePool:      newTracePool(),
				origins:        &originRegistry{},
				processManager: &pm.ProcessManager{},
			}
			origin, err := tr.origins.Register(&samples.TypeMetadata{})
			require.NoError(t, err)
			header := support.Trace{
				Pid:              123,
				Origin:           origin,
				Kernel_frame_end: 8,
				Frame_data_end:   16,
				Num_frames:       1,
			}
			frames := []uint64{0x1234, 0x5678}
			data := append([]byte(nil), pfunsafe.FromSlice(frames)...)
			if tc.threadPayload != nil {
				data = append(data, tc.threadPayload...)
				header.Thread_label_end = uint16(len(data))
				// Padding is not part of the payload and need not be zeroed.
				data = append(data, bytes.Repeat([]byte{0xff}, (-len(data))&7)...)
			}
			if tc.goLabels {
				label := support.GolangLabel{}
				copy(label.Key[:], "tenant")
				copy(label.Val[:], "go")
				data = append(data, pfunsafe.FromPointer(&label)...)
				header.Golang_label_end = uint16(len(data))
			}
			if tc.threadEnd != 0 {
				header.Thread_label_end = tc.threadEnd
			}
			if tc.goEnd != 0 {
				header.Golang_label_end = tc.goEnd
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
			if tc.goLabels {
				require.Equal(t, map[libpf.String]libpf.String{
					libpf.Intern("tenant"): libpf.Intern("go"),
				}, trace.CustomLabels)
			} else {
				require.Nil(t, trace.CustomLabels)
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
	raw := append(append(append([]byte(nil), payload...), padding...), pfunsafe.FromPointer(&goLabel)...)
	vd := variableDataDecoder{raw: raw}
	data, err := vd.decodeBytes(3, "thread label")
	require.NoError(t, err)
	var resolver threadLabelResolver
	labels := resolver.resolve(data, testThreadLabelDecoder(func(data []byte) (libpf.ThreadLabels, int) {
		require.Equal(t, payload, data)
		require.Equal(t, len(data), cap(data))
		// Appending must not overwrite the following padding or Go label.
		extended := append(data, bytes.Repeat([]byte{0}, 16)...)
		require.Len(t, extended, 19)
		return libpf.ThreadLabels{
			libpf.Intern("tenant"): libpf.Intern("thread"),
			libpf.Intern("route"):  libpf.Intern("/orders"),
		}, 0
	}))
	require.Equal(t, padding, raw[3:8])
	data, err = vd.decodeBytes(uint16(len(raw)), "golang label")
	require.NoError(t, err)
	var validator customLabelValidator
	labels = validator.decode(data, labels)
	require.Equal(t, libpf.ThreadLabels{
		libpf.Intern("tenant"): libpf.Intern("go"),
		libpf.Intern("route"):  libpf.Intern("/orders"),
	}, labels)
}

type testThreadLabelDecoder func([]byte) (libpf.ThreadLabels, int)

func (d testThreadLabelDecoder) DecodeLabels(data []byte) (libpf.ThreadLabels, int) {
	return d(data)
}

func TestThreadLabelResolver(t *testing.T) {
	var r threadLabelResolver
	payload := []byte{0, 1, 'x', 1, 4, 'y'}
	want := libpf.ThreadLabels{libpf.Intern("tenant"): libpf.Intern("x")}
	decoder := testThreadLabelDecoder(func(data []byte) (libpf.ThreadLabels, int) {
		require.Equal(t, payload, data)
		return want, 2
	})
	require.Equal(t, want, r.resolve(payload, decoder))
	require.Nil(t, r.resolve(payload, nil))

	byID := map[metrics.MetricID]metrics.MetricValue{}
	for _, m := range r.getAndResetMetrics() {
		byID[m.ID] = m.Value
	}
	// Distinct values, so swapping the two IDs would fail.
	require.Equal(t, metrics.MetricValue(1), byID[metrics.IDThreadContextLabelsNoDecoder])
	require.Equal(t, metrics.MetricValue(2), byID[metrics.IDThreadContextDroppedEntriesUndecodable])

	for _, m := range r.getAndResetMetrics() {
		require.Zero(t, m.Value, m.ID)
	}
}
