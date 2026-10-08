// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

// testFrames returns a minimal non-empty frame list so that HandleAlloc caches
// it (the cache is only populated for len(frames) > 0).
func testFrames() libpf.Frames {
	f := make(libpf.Frames, 0, 1)
	f.Append(&libpf.Frame{Type: libpf.NativeFrame, AddressOrLineno: 0x1000})
	return f
}

// metricValue extracts a single metric value from a GetAndResetMetrics result.
// Returns -1 if the metric is absent so a missing metric fails assertions.
func metricValue(ms []metrics.Metric, id metrics.MetricID) metrics.MetricValue {
	for _, m := range ms {
		if m.ID == id {
			return m.Value
		}
	}
	return -1
}

func TestTracker_AllocThenFreeRemovesEntry(t *testing.T) {
	tr := NewTracker()
	tr.SetPIDLiveHeapSupport(1, true)

	tr.HandleAlloc(1, 0xdead, libpf.NewTraceHash(0, 1), 100, testFrames())
	require.Equal(t, 1, tr.LiveCount())

	snap := tr.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, int64(100), snap[0].Space)
	assert.Equal(t, int64(1), snap[0].Objects)

	assert.True(t, tr.HandleFree(1, 0xdead), "freeing a live ptr returns true")
	assert.Equal(t, 0, tr.LiveCount())
	assert.False(t, tr.HandleFree(1, 0xbeef), "freeing an unknown ptr returns false")
}

func TestTracker_UntrackedPIDIgnoredButCounted(t *testing.T) {
	tr := NewTracker()
	// PID 1 was never marked live-heap-supported.
	tr.HandleAlloc(1, 0xdead, libpf.NewTraceHash(0, 1), 100, testFrames())

	assert.Equal(t, 0, tr.LiveCount(), "alloc from unsupported PID must not be tracked")
	assert.Equal(t, metrics.MetricValue(1),
		metricValue(tr.GetAndResetMetrics(), metrics.IDHeapAllocSamples),
		"the received sample is still counted")
}

func TestTracker_CountsAllReceivedIncludingZeroPtr(t *testing.T) {
	tr := NewTracker()
	tr.SetPIDLiveHeapSupport(1, true)

	// ptr == 0 means eBPF did not live-track the alloc (dropped / non-live /
	// first sighting): counted as received, never added to the live set.
	tr.HandleAlloc(1, 0, libpf.NewTraceHash(0, 1), 100, nil)
	assert.Equal(t, 0, tr.LiveCount(), "ptr == 0 must not enter the live set")

	tr.HandleAlloc(1, 0xdead, libpf.NewTraceHash(0, 2), 100, testFrames())
	assert.Equal(t, 1, tr.LiveCount())

	assert.Equal(t, metrics.MetricValue(2),
		metricValue(tr.GetAndResetMetrics(), metrics.IDHeapAllocSamples),
		"both received allocs are counted")
}

func TestTracker_DuplicatePtrOverwrites(t *testing.T) {
	tr := NewTracker()
	tr.SetPIDLiveHeapSupport(1, true)

	h1 := libpf.NewTraceHash(0, 1)
	h2 := libpf.NewTraceHash(0, 2)

	tr.HandleAlloc(1, 0xaaa, h1, 100, testFrames())
	require.Equal(t, 1, tr.LiveCount())

	// A duplicate ptr overwrites the existing entry and refreshes hash/weight.
	tr.HandleAlloc(1, 0xaaa, h2, 200, testFrames())
	assert.Equal(t, 1, tr.LiveCount())

	snap := tr.Snapshot()
	require.Len(t, snap, 1)
	assert.Equal(t, h2, snap[0].TraceHash, "duplicate ptr refreshes the trace hash")
	assert.Equal(t, int64(200), snap[0].Space, "duplicate ptr refreshes the weight")
}

func TestTracker_SnapshotAggregatesByPIDAndStack(t *testing.T) {
	tr := NewTracker()
	tr.SetPIDLiveHeapSupport(1, true)
	tr.SetPIDLiveHeapSupport(2, true)

	h := libpf.NewTraceHash(0, 1)
	tr.HandleAlloc(1, 0xa, h, 100, testFrames())
	tr.HandleAlloc(1, 0xb, h, 200, testFrames()) // same PID + stack
	tr.HandleAlloc(2, 0xc, h, 50, testFrames())  // same stack, different PID

	snap := tr.Snapshot()
	require.Len(t, snap, 2, "aggregation is per (PID, stack)")

	byPID := map[libpf.PID]InuseEntry{}
	for _, e := range snap {
		byPID[e.PID] = e
	}
	assert.Equal(t, int64(300), byPID[1].Space)
	assert.Equal(t, int64(2), byPID[1].Objects)
	assert.Equal(t, int64(50), byPID[2].Space)
	assert.Equal(t, int64(1), byPID[2].Objects)
}

func TestTracker_SnapshotPrunesUnreferencedFrames(t *testing.T) {
	tr := NewTracker()
	tr.SetPIDLiveHeapSupport(1, true)

	h1 := libpf.NewTraceHash(0, 1)
	h2 := libpf.NewTraceHash(0, 2)
	tr.HandleAlloc(1, 0xa, h1, 100, testFrames())
	tr.HandleAlloc(1, 0xb, h2, 100, testFrames())

	tr.mu.Lock()
	require.Len(t, tr.frames, 2)
	tr.mu.Unlock()

	// Free the only allocation referencing h2.
	tr.HandleFree(1, 0xb)
	tr.mu.Lock()
	assert.Len(t, tr.frames, 2, "HandleFree must not prune the frame cache")
	tr.mu.Unlock()

	// Snapshot prunes the now-unreferenced h2.
	tr.Snapshot()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	assert.Len(t, tr.frames, 1, "Snapshot prunes unreferenced frame-cache entries")
	_, ok := tr.frames[h1]
	assert.True(t, ok, "the still-referenced stack is retained")
}

func TestTracker_HandleProcessExit(t *testing.T) {
	tr := NewTracker()
	tr.SetPIDLiveHeapSupport(1, true)
	tr.SetPIDLiveHeapSupport(2, true)

	h := libpf.NewTraceHash(0, 1)
	tr.HandleAlloc(1, 0xa, h, 100, testFrames())
	tr.HandleAlloc(1, 0xb, h, 100, testFrames())
	tr.HandleAlloc(2, 0xc, h, 100, testFrames())

	ptrs := tr.HandleProcessExit(1)
	assert.ElementsMatch(t, []uint64{0xa, 0xb}, ptrs, "returns the exited PID's live ptrs")
	assert.Equal(t, 1, tr.LiveCount(), "other PIDs are untouched")

	// Exit clears the PID's live-heap support, so later allocs are ignored.
	tr.HandleAlloc(1, 0xd, h, 100, testFrames())
	assert.Equal(t, 1, tr.LiveCount())
}

func TestTracker_GetAndResetMetrics(t *testing.T) {
	tr := NewTracker()
	tr.SetPIDLiveHeapSupport(1, true)

	tr.HandleAlloc(1, 0xa, libpf.NewTraceHash(0, 1), 100, testFrames())
	tr.HandleAlloc(1, 0xb, libpf.NewTraceHash(0, 2), 100, testFrames())
	tr.HandleFree(1, 0xa)

	m := tr.GetAndResetMetrics()
	assert.Equal(t, metrics.MetricValue(2), metricValue(m, metrics.IDHeapAllocSamples))
	assert.Equal(t, metrics.MetricValue(1), metricValue(m, metrics.IDHeapFreeSamples))

	// Interval counters reset after collection.
	m2 := tr.GetAndResetMetrics()
	assert.Equal(t, metrics.MetricValue(0), metricValue(m2, metrics.IDHeapAllocSamples))
	assert.Equal(t, metrics.MetricValue(0), metricValue(m2, metrics.IDHeapFreeSamples))
}
