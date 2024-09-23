//go:build !arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
)

// insertSynthStackDeltas adds synthetic stack-deltas to the given SDMM. On non-ARM64, this is
// currently unused.
func (pm *ProcessManager) insertSynthStackDeltas(_ host.FileID, _ *pfelf.File) error {
	return nil
}
