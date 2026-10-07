// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
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
		name       string
		goLabels   bool
		threadEnd  uint16
		threadSize uint16
		wantError  bool
		wantDrop   int64
	}{
		{name: "no labels"},
		{name: "Go labels", goLabels: true},
		{name: "thread context without schema", threadEnd: 3, threadSize: 3, wantDrop: 1},
		{name: "both sections without schema", goLabels: true, threadEnd: 11, threadSize: 3, wantDrop: 1},
		{name: "empty attributes skip schema lookup", threadEnd: 3},
		{name: "empty section", threadEnd: 2},
		{name: "overlapping section", goLabels: true, threadEnd: 9, threadSize: 3, wantError: true},
		{name: "end beyond record", threadEnd: 4, threadSize: 3, wantError: true},
		{name: "size beyond payload", threadEnd: 3, threadSize: 7, wantError: true},
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
				Kernel_frame_end: 1,
				Frame_data_end:   2,
				Num_frames:       1,
				Thread_label_end: tc.threadEnd,
			}
			frames := []uint64{0x1234, 0x5678}
			data := append([]byte(nil), pfunsafe.FromSlice(frames)...)
			if tc.goLabels {
				label := support.GolangLabel{}
				copy(label.Key[:], "tenant")
				copy(label.Val[:], "go")
				data = append(data, pfunsafe.FromPointer(&label)...)
				header.Golang_label_end = uint16(len(data) / 8)
			}
			if tc.threadEnd != 0 && int(tc.threadEnd) != len(data)/8 {
				labels := support.ThreadLabelData{Size: tc.threadSize}
				data = append(data, pfunsafe.FromPointer(&labels)...)
				// One encoded attribute followed by nonzero ring-buffer padding.
				data = append(data, 0, 1, 'x', 0xff, 0xff, 0xff)
			}
			header.Variable_data_end = uint16(len(data) / 8)
			raw := append(pfunsafe.FromPointer(&header), data...)
			trace, err := tr.loadBpfTrace(raw)
			if tc.wantError {
				require.ErrorIs(t, err, errRecordUnexpectedSize)
				return
			}
			require.NoError(t, err)
			require.Equal(t, frames, trace.FrameData)
			require.Equal(t, uint16(1), trace.NumKernelFrames)
			if tc.goLabels {
				require.Equal(t, map[libpf.String]libpf.String{
					libpf.Intern("tenant"): libpf.Intern("go"),
				}, trace.CustomLabels)
			} else {
				require.Nil(t, trace.CustomLabels)
			}
			require.Equal(t, tc.wantDrop, tr.threadContextLabels.droppedSamplesNoSchema.Load())
		})
	}
}

func TestThreadLabelPayload(t *testing.T) {
	data := []byte{0, 1, 'x', 0xff, 0xff, 0xff}
	for _, tc := range []struct {
		name      string
		size      uint16
		want      []byte
		wantError bool
	}{
		{name: "padding excluded", size: 3, want: data[:3]},
		{name: "empty attributes", want: data[:0]},
		{name: "entire payload", size: 6, want: data},
		{name: "oversized payload", size: 7, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := support.ThreadLabelData{Size: tc.size}
			section := append(pfunsafe.FromPointer(&header), data...)
			payload, err := threadLabelPayload(section)
			if tc.wantError {
				require.ErrorIs(t, err, errRecordUnexpectedSize)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, payload)
		})
	}
	t.Run("truncated header", func(t *testing.T) {
		_, err := threadLabelPayload(make([]byte, support.Sizeof_ThreadLabelData-1))
		require.ErrorIs(t, err, errRecordUnexpectedSize)
	})
}

type testThreadLabelDecoder func([]byte) (libpf.ThreadLabels, int)

func (d testThreadLabelDecoder) DecodeLabels(data []byte) (libpf.ThreadLabels, int) {
	return d(data)
}

func TestThreadContextCustomLabels(t *testing.T) {
	var tr Tracer
	payload := []byte{0, 1, 'x', 1, 4, 'y'}
	want := libpf.ThreadLabels{libpf.Intern("tenant"): libpf.Intern("x")}
	decoder := testThreadLabelDecoder(func(data []byte) (libpf.ThreadLabels, int) {
		require.Equal(t, payload, data)
		return want, 1
	})
	require.Equal(t, map[libpf.String]libpf.String(want), tr.threadContextCustomLabels(payload, decoder))
	require.Nil(t, tr.threadContextCustomLabels(payload, nil))
	require.Equal(t, int64(1), tr.threadContextLabels.droppedEntriesUndecodable.Load())
	require.Equal(t, int64(1), tr.threadContextLabels.droppedSamplesNoSchema.Load())
	for _, metric := range tr.threadContextLabels.getAndResetMetrics() {
		require.EqualValues(t, 1, metric.Value)
	}
	for _, metric := range tr.threadContextLabels.getAndResetMetrics() {
		require.Zero(t, metric.Value)
	}
}
