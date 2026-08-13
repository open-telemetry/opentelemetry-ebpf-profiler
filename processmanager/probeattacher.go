// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// ProbeAttacher is implemented by probes that need to attach to individual processes.
// ProcessManager calls Match for each new executable mapping; if Match returns true,
// Attach is called for that mapping. Attach may therefore be called multiple times for
// the same PID if the process has more than one matching mapping.
// Detach is called exactly once per PID when the process exits.
//
// Implementations must not call back into ProcessManager during Attach or Detach,
// as those methods are invoked while the ProcessManager's internal lock is held.
type ProbeAttacher interface {
	// Match returns true if this probe wants to attach to a process that has the
	// given executable mapping. Must be cheap and must not block.
	Match(pr process.Process, mapping *process.RawMapping) bool

	// Attach is called for each matching mapping seen for a PID.
	// The implementation is responsible for opening and managing per-PID
	// kernel resources (e.g. a uprobe link restricted to that PID).
	Attach(pr process.Process) error

	// Detach is called when a matched process exits. The implementation must
	// close all per-process resources opened in Attach.
	Detach(pid libpf.PID)
}

// RegisterProbeAttacher registers a per-process probe attacher. SynchronizeProcess
// calls Match for each new executable mapping; Attach is called once for any PID
// that has at least one matching mapping. Detach is called on process exit.
func (pm *ProcessManager) RegisterProbeAttacher(a ProbeAttacher) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.probeAttachers = append(pm.probeAttachers, a)
}
