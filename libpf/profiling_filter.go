// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

// ProcessFilter is the decision-making interface for profiling policies.
// The core calls these methods but does NOT implement them — the top-level
// application provides the implementation, enabling pluggable filtering
// without modifying the core.
type ProcessFilter interface {
	// CPUFilter returns the PID filter for CPU profiling (eBPF map filtering).
	CPUFilter() PIDFilter

	// MemFilter returns the PID filter for memory profiling iteration.
	MemFilter() PIDFilter

	// ShouldProfileMem determines whether to start memory profiling hooks
	// for the given process and its detected runtime language.
	ShouldProfileMem(pid PID, lang InterpreterType) bool
}
