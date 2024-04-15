/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package nativeunwind

import (
	"github.com/elastic/otel-profiling-agent/host"
	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
)

type Statistics struct {
	// Number of times for a hit of a cache entry.
	Hit uint64
	// Number of times for a miss of a cache entry.
	Miss uint64

	// Number of times extracting stack deltas failed.
	ExtractionErrors uint64
}

// StackDeltaProvider defines an interface for types that provide access to the stack deltas from
// executables.
type StackDeltaProvider interface {
	// GetIntervalStructuresForFile inspects a single executable and extracts data that is needed
	// to rebuild the stack for traces of this executable.
	GetIntervalStructuresForFile(fileID host.FileID, elfRef *pfelf.Reference,
		interval *sdtypes.IntervalData) error

	// GetAndResetStatistics returns the internal statistics for this provider and resets all
	// values to 0.
	GetAndResetStatistics() Statistics
}
