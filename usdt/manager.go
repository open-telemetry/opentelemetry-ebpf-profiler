// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"fmt"

	cebpf "github.com/cilium/ebpf"
	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/util"
)

// parseCacheSize bounds the number of distinct backing files for which we
// keep cached `.note.stapsdt` parse results. One entry per binary/library
// the profiler has ever scanned. Matched to elfInfoCacheSize in
// processmanager so the two caches age at similar rates.
const parseCacheSize = 16384

// Manager holds process-independent state for USDT attachment: BPF program
// handles and a parse cache keyed by file identity.
//
// One Manager per profiler instance. The parse cache is concurrency-safe;
// the rest of the Manager is read-only after construction.
//
// RefCtrOffset PMU support is required (Linux 4.20+) and the profiler's
// minimum kernel is 5.10, so we always pass the semaphore offset through
// without a capability check.
type Manager struct {
	// progs holds the BPF program to attach for each ProbeKind. Loaded by
	// the tracer alongside the rest of the collection spec.
	progs map[ProbeKind]*cebpf.Program

	// parseCache deduplicates `.note.stapsdt` parsing (via
	// github.com/parca-dev/usdt, see discovery.go) across processes that
	// share the same backing file. Empty results are cached too so that
	// probe-less binaries are not re-parsed on every Reconcile.
	parseCache *lru.SyncedLRU[util.OnDiskFileIdentifier, []parsedProbe]
}

// NewManager constructs a Manager. progs must contain one non-nil entry per
// ProbeKind the caller wants attached; kinds without a program will be
// skipped at reconcile time.
//
// Returns (nil, nil) if progs is empty, so the tracer wiring can disable
// USDT support by simply passing an empty map.
func NewManager(progs map[ProbeKind]*cebpf.Program) (*Manager, error) {
	if len(progs) == 0 {
		return nil, nil
	}
	for kind, prog := range progs {
		if prog == nil {
			return nil, fmt.Errorf("usdt: nil BPF program for probe kind %d", kind)
		}
	}

	parseCache, err := lru.NewSynced[util.OnDiskFileIdentifier, []parsedProbe](
		parseCacheSize, util.OnDiskFileIdentifier.Hash32)
	if err != nil {
		return nil, fmt.Errorf("usdt: build parse cache: %w", err)
	}

	return &Manager{
		progs:      progs,
		parseCache: parseCache,
	}, nil
}

// Close releases manager-owned resources. Per-PID links are owned by the
// Instances and closed via Instance.Detach.
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.parseCache.Purge()
	return nil
}
