/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package nativeunwind

import (
	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
)

// IntervalCache defines an interface that allows one to save and load interval data for use in the
// unwinding of native stacks. It should be implemented by types that want to provide caching to
// `GetIntervalStructures`.
type IntervalCache interface {
	// HasIntervals returns true if interval data exists in the cache for a file with the provided
	// ID, or false otherwise.
	HasIntervals(exeID host.FileID) bool
	// GetIntervalData loads the interval data from the cache that is associated with `exeID`
	// into `interval`.
	GetIntervalData(exeID host.FileID, interval *stackdeltatypes.IntervalData) error
	// SaveIntervalData stores the provided `interval` that is associated with `exeID`
	// in the cache.
	SaveIntervalData(exeID host.FileID, interval *stackdeltatypes.IntervalData) error
	// GetCurrentCacheSize returns the current size of the cache in bytes. Or an error
	// otherwise.
	GetCurrentCacheSize() (uint64, error)
	// GetAndResetHitMissCounters returns the current hit and miss counters of the cache
	// and resets them to 0.
	GetAndResetHitMissCounters() (hit, miss uint64)
}
