// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"fmt"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/processmanager"
)

// Discoverer finds USDT attachment points and caches results by backing-file identity.
// The parse cache is not synchronized; callers serialize access via the
// processmanager lock (see processinfo.Attach).
type Discoverer struct {
	parseCache *lru.LRU[libpf.FileID, []AttachmentPoint]
}

// NewDiscoverer constructs a USDT discoverer.
func NewDiscoverer() (*Discoverer, error) {
	parseCache, err := lru.New[libpf.FileID, []AttachmentPoint](
		processmanager.ELFInfoCacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("usdt: build parse cache: %w", err)
	}
	return &Discoverer{parseCache: parseCache}, nil
}
