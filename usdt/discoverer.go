// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"fmt"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/util"
)

// parseCacheSize bounds the number of distinct backing files for which we
// retain parsed `.note.stapsdt` results. It matches the process manager's ELF
// cache size so the two caches age at a similar rate.
const parseCacheSize = 16384

// Discoverer finds USDT attachment points and caches results by backing-file identity.
type Discoverer struct {
	parseCache *lru.SyncedLRU[util.OnDiskFileIdentifier, []AttachmentPoint]
}

// NewDiscoverer constructs a USDT discoverer.
func NewDiscoverer() (*Discoverer, error) {
	parseCache, err := lru.NewSynced[util.OnDiskFileIdentifier, []AttachmentPoint](
		parseCacheSize, util.OnDiskFileIdentifier.Hash32)
	if err != nil {
		return nil, fmt.Errorf("usdt: build parse cache: %w", err)
	}
	return &Discoverer{parseCache: parseCache}, nil
}
