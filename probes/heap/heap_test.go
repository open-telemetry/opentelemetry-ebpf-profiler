// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import (
	"math"
	"testing"
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
