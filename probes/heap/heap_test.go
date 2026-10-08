// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package heap

import (
	"math"
	"slices"
	"testing"

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
