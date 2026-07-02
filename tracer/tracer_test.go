// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"testing"
	"unique"

	cebpf "github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/kallsyms"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

// Make accessible for testing
func (t *Tracer) GetEbpfMaps() map[string]*cebpf.Map {
	return t.ebpfMaps
}

func TestKernelFrameCacheMetrics(t *testing.T) {
	tracer := &Tracer{}
	tracer.kernelFrameCacheHit.Add(1)
	tracer.kernelFrameCacheMiss.Add(1)

	got := tracer.kernelFrameCacheMetrics()
	want := []metrics.Metric{
		{ID: metrics.IDKernelFrameCacheHit, Value: 1},
		{ID: metrics.IDKernelFrameCacheMiss, Value: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d metrics, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("metric %d: expected %+v, got %+v", i, want[i], got[i])
		}
	}

	got = tracer.kernelFrameCacheMetrics()
	want = []metrics.Metric{
		{ID: metrics.IDKernelFrameCacheHit, Value: 0},
		{ID: metrics.IDKernelFrameCacheMiss, Value: 0},
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("metric %d after reset: expected %+v, got %+v", i, want[i], got[i])
		}
	}
}

func TestSymbolizeKernelFramesIgnoresInvalidCacheEntries(t *testing.T) {
	kernelFrameCache, err := lru.New[libpf.Address, kernelFrameCacheValue](
		kernelFrameCacheSize, libpf.Address.Hash32)
	if err != nil {
		t.Fatalf("failed to create kernel frame cache: %v", err)
	}

	cachedFrame := unique.Make(libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0,
		FunctionName:    libpf.Intern("cached"),
	})
	kernelFrameCache.Add(0x1234, kernelFrameCacheValue{
		generation: kallsyms.Generation(2),
		frame:      cachedFrame,
	})

	tracer := &Tracer{
		kernelSymbolizer: &kallsyms.Symbolizer{},
		kernelFrameCache: kernelFrameCache,
	}

	frames := tracer.symbolizeKernelFrames([]uint64{0x1234}, nil)
	if len(frames) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(frames))
	}
	if frames[0] == cachedFrame {
		t.Fatalf("expected stale cache entry to be ignored")
	}

	got := tracer.kernelFrameCacheMetrics()
	want := []metrics.Metric{
		{ID: metrics.IDKernelFrameCacheHit, Value: 0},
		{ID: metrics.IDKernelFrameCacheMiss, Value: 1},
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d metrics, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("metric %d: expected %+v, got %+v", i, want[i], got[i])
		}
	}
}
