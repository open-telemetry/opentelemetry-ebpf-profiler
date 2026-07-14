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
)

// Make accessible for testing
func (t *Tracer) GetEbpfMaps() map[string]*cebpf.Map {
	return t.ebpfMaps
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
}
