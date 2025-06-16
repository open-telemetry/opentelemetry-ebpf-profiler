// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package times

import (
	"runtime"
	"sort"
	"sync/atomic"
	"time"
)

const (
	// Number of timing samples to use when retrieving system boot time.
	sampleSize = 5
)

var (
	// Monotonic-to-unixtime delta that can be added to a monotonic (CLOCK_MONOTONIC)
	// timestamp to convert it to time-since-epoch.
	bootTimeUnixNano atomic.Int64
)

// StartRealtimeSync calculates a delta between the monotonic clock
// (CLOCK_MONOTONIC, rebased to unixtime) and the realtime clock. If syncInterval is
// greater than zero, it also starts a goroutine to perform that calculation periodically.
func StartRealtimeSync() {
	bootTimeUnixNano.Store(getBootTimeUnixNano())
}

// getBootTimeUnixNano returns system boot time in nanoseconds since the
// epoch, temporarily locking the calling goroutine to its OS thread.
func getBootTimeUnixNano() int64 {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	samples := make([]struct {
		t1    time.Time
		ktime int64
		t2    time.Time
	}, sampleSize)

	for i := range samples {
		// To avoid noise from scheduling / other delays, we perform a
		// series of measurements and pick the one with the lowest delta.
		samples[i].t1 = time.Now()
		samples[i].ktime = int64(GetKTime())
		samples[i].t2 = time.Now()
	}

	sort.Slice(samples, func(i, j int) bool {
		di := samples[i].t2.UnixNano() - samples[i].t1.UnixNano()
		dj := samples[j].t2.UnixNano() - samples[j].t1.UnixNano()
		if di < 0 {
			di = -di
		}
		if dj < 0 {
			dj = -dj
		}
		return di < dj
	})

	// This should never be negative, as t1.UnixNano() >> ktime
	return samples[0].t1.UnixNano() - samples[0].ktime
}
