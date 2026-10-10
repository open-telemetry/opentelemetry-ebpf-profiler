// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
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
		threadSection bool
		threadSize    uint16
		// Overrides the Thread_label_end matching the data actually written.
		threadEnd uint16
		wantError bool
		wantDrop  int64
	}{
		{name: "no labels"},
		{name: "both sections without schema", goLabels: true, threadSection: true,
			threadSize: 3, wantDrop: 1},
		{name: "section with no attributes", threadSection: true},
		{name: "zero-length section", threadEnd: 2},
		{name: "overlapping section", threadSection: true, threadSize: 3, threadEnd: 1,
			wantError: true},
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
			}
			frames := []uint64{0x1234, 0x5678}
			data := append([]byte(nil), pfunsafe.FromSlice(frames)...)
			if tc.threadSection {
				labels := support.ThreadLabelData{Size: tc.threadSize}
				data = append(data, pfunsafe.FromPointer(&labels)...)
				// One encoded attribute followed by nonzero alignment padding.
				data = append(data, 0, 1, 'x', 0xff, 0xff, 0xff)
				header.Thread_label_end = uint16(len(data) / 8)
			}
			if tc.goLabels {
				label := support.GolangLabel{}
				copy(label.Key[:], "tenant")
				copy(label.Val[:], "go")
				data = append(data, pfunsafe.FromPointer(&label)...)
				header.Golang_label_end = uint16(len(data) / 8)
			}
			if tc.threadEnd != 0 {
				header.Thread_label_end = tc.threadEnd
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

func TestThreadLabelPayload(t *testing.T) {
	data := []byte{0, 1, 'x', 0xff, 0xff, 0xff}
	for _, tc := range []struct {
		name      string
		size      uint16
		want      []byte
		wantError bool
	}{
		{name: "padding excluded", size: 3, want: data[:3]},
		{name: "entire payload", size: 6, want: data},
		{name: "oversized payload", size: 7, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			section := make([]uint64, 1)
			raw := pfunsafe.FromSlice(section)
			header := support.ThreadLabelData{Size: tc.size}
			copy(raw, pfunsafe.FromPointer(&header))
			copy(raw[support.Sizeof_ThreadLabelData:], data)
			payload, err := threadLabelPayload(section)
			if tc.wantError {
				require.ErrorIs(t, err, errRecordUnexpectedSize)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, payload)
		})
	}
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
