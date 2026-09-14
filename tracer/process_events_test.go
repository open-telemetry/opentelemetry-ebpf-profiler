// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"testing"

	"github.com/elastic/go-perf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestMmapRecordPIDTID(t *testing.T) {
	want := libpf.PIDTID(uint64(123)<<32 | 456)

	got, ok := mmapRecordPIDTID(&perf.MmapRecord{Pid: 123, Tid: 456})
	require.True(t, ok)
	require.Equal(t, want, got)

	_, ok = mmapRecordPIDTID(&perf.LostRecord{})
	require.False(t, ok)
}
