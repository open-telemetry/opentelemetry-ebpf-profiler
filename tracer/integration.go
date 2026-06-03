//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	cebpf "github.com/cilium/ebpf"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// GetEbpfMaps exposes the tracer's eBPF maps for integration testing. Gated
// behind the integration build tag so it is not part of the released
// binary's public surface.
func (t *Tracer) GetEbpfMaps() map[string]*cebpf.Map {
	return t.ebpfMaps
}

// ForceProcessPID enqueues an immediate PID processing event for the given
// PID, driving interpreter loader discovery against that process's
// /proc/<pid>/maps without waiting for an on-CPU sample to surface it.
// Used by integration tests to install probes on the test process itself.
func (t *Tracer) ForceProcessPID(pid libpf.PID) {
	pidTID := libpf.PIDTID(uint64(pid)<<32 | uint64(pid))
	select {
	case t.pidEvents <- pidTID:
	default:
	}
}
