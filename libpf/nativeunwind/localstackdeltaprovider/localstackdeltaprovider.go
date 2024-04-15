/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package localstackdeltaprovider

import (
	"fmt"
	"sync/atomic"

	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind/elfunwindinfo"
	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	log "github.com/sirupsen/logrus"
)

// LocalStackDeltaProvider extracts stack deltas from executables available
// on the local filesystem.
type LocalStackDeltaProvider struct {
	// Metrics
	hitCount             atomic.Uint64
	missCount            atomic.Uint64
	extractionErrorCount atomic.Uint64

	// cache provides access to a cache of interval data that is preserved across runs of
	// the agent, so that we only need to process an executable to extract intervals the
	// first time a run of the agent sees the executable.
	cache nativeunwind.IntervalCache
}

// Compile time check that the LocalStackDeltaProvider implements its interface correctly.
var _ nativeunwind.StackDeltaProvider = (*LocalStackDeltaProvider)(nil)

// New creates a local stack delta provider that uses the given cache to provide
// stack deltas for executables.
func New(cache nativeunwind.IntervalCache) *LocalStackDeltaProvider {
	return &LocalStackDeltaProvider{
		cache: cache,
	}
}

// GetIntervalStructuresForFile builds the stack delta information for a single executable.
func (provider *LocalStackDeltaProvider) GetIntervalStructuresForFile(fileID host.FileID,
	elfRef *pfelf.Reference, interval *sdtypes.IntervalData) error {
	// Return cached data if it's available
	if provider.cache.HasIntervals(fileID) {
		var err error
		if err = provider.cache.GetIntervalData(fileID, interval); err == nil {
			provider.hitCount.Add(1)
			return nil
		}
		provider.missCount.Add(1)
		log.Debugf("Failed to get stack delta for %s from cache: %v",
			elfRef.FileName(), err)
	}

	err := elfunwindinfo.ExtractELF(elfRef, interval)
	if err != nil {
		provider.extractionErrorCount.Add(1)
		return fmt.Errorf("failed to extract stack deltas from %s: %v",
			elfRef.FileName(), err)
	}

	return provider.cache.SaveIntervalData(fileID, interval)
}

func (provider *LocalStackDeltaProvider) GetAndResetStatistics() nativeunwind.Statistics {
	return nativeunwind.Statistics{
		Hit:              provider.hitCount.Swap(0),
		Miss:             provider.missCount.Swap(0),
		ExtractionErrors: provider.extractionErrorCount.Swap(0),
	}
}
