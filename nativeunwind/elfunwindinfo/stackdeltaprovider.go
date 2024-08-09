/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package elfunwindinfo

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/nativeunwind"
	sdtypes "github.com/open-telemetry/opentelemetry-ebpf-profiler/nativeunwind/stackdeltatypes"
)

// ELFStackDeltaProvider extracts stack deltas from ELF executables available
// via the pfelf.File interface.
type ELFStackDeltaProvider struct {
	// Metrics
	successCount         atomic.Uint64
	extractionErrorCount atomic.Uint64
}

// Compile time check that the ELFStackDeltaProvider implements its interface correctly.
var _ nativeunwind.StackDeltaProvider = (*ELFStackDeltaProvider)(nil)

// NewStackDeltaProvider creates a stack delta provider using the ELF eh_frame extraction.
func NewStackDeltaProvider() nativeunwind.StackDeltaProvider {
	return &ELFStackDeltaProvider{}
}

// GetIntervalStructuresForFile builds the stack delta information for a single executable.
func (provider *ELFStackDeltaProvider) GetIntervalStructuresForFile(_ host.FileID,
	elfRef *pfelf.Reference, interval *sdtypes.IntervalData) error {
	err := ExtractELF(elfRef, interval)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			provider.extractionErrorCount.Add(1)
		}
		return fmt.Errorf("failed to extract stack deltas from %s: %w",
			elfRef.FileName(), err)
	}
	provider.successCount.Add(1)
	return nil
}

func (provider *ELFStackDeltaProvider) GetAndResetStatistics() nativeunwind.Statistics {
	return nativeunwind.Statistics{
		Success:          provider.successCount.Swap(0),
		ExtractionErrors: provider.extractionErrorCount.Swap(0),
	}
}
