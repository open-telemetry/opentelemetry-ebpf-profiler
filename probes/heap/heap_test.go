// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import (
	"math"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func TestDeriveAllocValues(t *testing.T) {
	meta := &samples.TraceEventMeta{
		ContextValues: []uint64{1000, 0xdeadbeef, 100},
	}
	got := deriveAllocValues([]int64{7}, meta)
	want := []int64{7, 1000, 10}
	if !slices.Equal(got, want) {
		t.Fatalf("deriveAllocValues() = %v, want %v", got, want)
	}
}

func TestAllocObjectsValue(t *testing.T) {
	tests := map[string]struct {
		weightedBytes int64
		size          uint64
		want          int64
	}{
		"exact multiple":      {weightedBytes: 1000, size: 100, want: 10},
		"single object":       {weightedBytes: 64, size: 64, want: 1},
		"unknown size":        {weightedBytes: 500, size: 0, want: 1},
		"weight below size":   {weightedBytes: 32, size: 64, want: 1},
		"rounds down":         {weightedBytes: 250, size: 100, want: 2},
		"size exceeds maxint": {weightedBytes: 1000, size: math.MaxUint64, want: 1},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := allocObjectsValue(tc.weightedBytes, tc.size); got != tc.want {
				t.Errorf("allocObjectsValue(%d, %d) = %d, want %d",
					tc.weightedBytes, tc.size, got, tc.want)
			}
		})
	}
}

func TestPreHandleTraceUsesContextValues(t *testing.T) {
	const pid libpf.PID = 42
	hp := &Probe{
		originAlloc: 1,
		originFree:  2,
		tracker:     NewTracker(),
	}
	hp.tracker.SetPIDLiveHeapSupport(pid, true)

	alloc := &libpf.EbpfTrace{
		Origin:        hp.originAlloc,
		PID:           pid,
		ContextValues: []uint64{1000, 0xdeadbeef, 100},
	}
	assert.True(t, hp.PreHandleTrace(alloc))
	assert.Equal(t, pid, hp.pendingAllocPID)
	assert.Equal(t, uint64(0xdeadbeef), hp.pendingAllocPtr)
	assert.Equal(t, int64(1000), hp.pendingAllocValue)

	hp.tracker.HandleAlloc(pid, 0xdeadbeef, libpf.NewTraceHash(1, 2), 1000, nil)
	free := &libpf.EbpfTrace{
		Origin:        hp.originFree,
		PID:           pid,
		ContextValues: []uint64{1000, 0xdeadbeef},
	}
	assert.False(t, hp.PreHandleTrace(free))
	assert.Empty(t, hp.tracker.Snapshot())
}

func TestDeriveInuseValues(t *testing.T) {
	meta := &samples.TraceEventMeta{ContextValues: []uint64{4096, 7}}
	assert.Equal(t, []int64{3, 4096, 7}, deriveInuseValues([]int64{3}, meta))
	assert.Equal(t, []int64{0, 0}, deriveInuseValues(nil, &samples.TraceEventMeta{}))
}

// TestProduceSnapshotsCarriesSpaceAndObjects pins the raw-value contract between
// the tracker snapshot and inuseProfileType.
func TestProduceSnapshotsCarriesSpaceAndObjects(t *testing.T) {
	const pid = 42
	hp := &Probe{tracker: NewTracker()}
	hp.tracker.SetPIDLiveHeapSupport(pid, true)

	hash := libpf.NewTraceHash(1, 2)
	hp.tracker.HandleAlloc(pid, 0x1000, hash, 1024, nil)
	hp.tracker.HandleAlloc(pid, 0x2000, hash, 3072, nil)

	profiles := hp.ProduceSnapshots()
	require.Len(t, profiles, 1)
	assert.Same(t, inuseProfileType, profiles[0].ProfileType)
	require.Len(t, profiles[0].Samples, 1)

	row := profiles[0].Samples[0]
	assert.Equal(t, libpf.PID(pid), row.PID)
	assert.Equal(t, []uint64{4096, 2}, row.ContextValues)

	meta := &samples.TraceEventMeta{ContextValues: row.ContextValues}
	assert.Equal(t, []int64{4096, 2}, inuseProfileType.AppendValues(nil, meta))
}
