//go:build !arm64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package processmanager

import (
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
)

// insertSynthStackDeltas adds synthetic stack-deltas to the given SDMM. On non-ARM64, this is
// currently unused.
func (pm *ProcessManager) insertSynthStackDeltas(_ host.FileID, _ *pfelf.File) error {
	return nil
}
