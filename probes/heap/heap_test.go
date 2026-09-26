// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestAllocObjectsValue(t *testing.T) {
	tests := map[string]struct {
		value int64
		extra [2]uint64
		want  int64
	}{
		"exact multiple":      {value: 1000, extra: [2]uint64{0, 100}, want: 10},
		"single object":       {value: 64, extra: [2]uint64{0, 64}, want: 1},
		"unknown size":        {value: 500, extra: [2]uint64{0, 0}, want: 1},
		"no extra recorded":   {value: 500, extra: [2]uint64{}, want: 1},
		"weight below size":   {value: 32, extra: [2]uint64{0, 64}, want: 1},
		"rounds down":         {value: 250, extra: [2]uint64{0, 100}, want: 2},
		"size exceeds maxint": {value: 1000, extra: [2]uint64{0, math.MaxUint64}, want: 1},
		"first extra unused":  {value: 1000, extra: [2]uint64{7, 100}, want: 10},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if got := allocObjectsValue(tc.value, tc.extra); got != tc.want {
				t.Errorf("allocObjectsValue(%d, %v) = %d, want %d",
					tc.value, tc.extra, got, tc.want)
			}
		})
	}
}

func TestInuseObjectsValue(t *testing.T) {
	// The live object count rides in ValueExtra[0]; the primary value (bytes)
	// is deliberately ignored, since the tracker counts both independently.
	if got := inuseObjectsValue(4096, [2]uint64{7, 0}); got != 7 {
		t.Errorf("inuseObjectsValue = %d, want 7", got)
	}
	if got := inuseObjectsValue(0, [2]uint64{}); got != 0 {
		t.Errorf("inuseObjectsValue with no extra = %d, want 0", got)
	}
}

// TestProduceSnapshotsCarriesSpaceAndObjects pins the contract between the tracker
// snapshot and inuseProfileType: bytes in Value, live object count in
// ValueExtra[0], which is where inuseObjectsValue reads it from.
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
	assert.Equal(t, int64(4096), row.Value, "Value is total live bytes")
	assert.Equal(t, [2]uint64{2, 0}, row.ValueExtra, "ValueExtra[0] is live object count")

	// The declared transform must read the count back out of the same slot.
	dp := inuseProfileType.DerivedProfiles[0]
	assert.Equal(t, int64(2), dp.Value(row.Value, row.ValueExtra))
}
