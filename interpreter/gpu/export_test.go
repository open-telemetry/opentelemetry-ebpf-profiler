// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu

import "go.opentelemetry.io/ebpf-profiler/libpf"

// RegisterTestFixer creates and registers a gpuTraceFixer for the given PID.
// For use in tests only.
func RegisterTestFixer(pid libpf.PID) {
	fixer := &gpuTraceFixer{
		timesAwaitingTraces: make(map[uint32][]CuptiTimingEvent),
		tracesAwaitingTimes: make(map[uint32]*SymbolizedCudaTrace),
	}
	gpuFixers.Store(pid, fixer)
}

// UnregisterTestFixer removes the fixer for the given PID.
func UnregisterTestFixer(pid libpf.PID) {
	gpuFixers.Delete(pid)
}
