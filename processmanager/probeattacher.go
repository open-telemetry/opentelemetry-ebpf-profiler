// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// ProbeAttacher is implemented by probes that need to attach to matching processes.
// SynchronizeProcess calls Match for each new executable mapping; Attach is called
// for every mapping where Match returns true, so a single process may trigger multiple
// Attach calls if it has more than one matching mapping.
// processPIDExit calls Detach once for each successful Attach when the process exits.
//
// Implementations must not call back into ProcessManager during Attach or Detach,
// as those methods are invoked while the ProcessManager's internal lock is held.
type ProbeAttacher interface {
	// Match returns true if this probe wants to attach to a process that has the
	// given executable mapping. Must be cheap and must not block.
	Match(pr process.Process, mapping *process.RawMapping) bool

	// Attach is called for each matching mapping of a process. It may therefore be
	// called more than once for the same process if multiple mappings match.
	// The implementation is responsible for opening and managing per-mapping
	// kernel resources (e.g. a uprobe link restricted to pid).
	Attach(pr process.Process) error

	// Detach is called when a matched process exits. The implementation must
	// close all per-process resources opened in Attach.
	Detach(pid libpf.PID)
}

// RegisterProbeAttacher registers a per-process probe attacher. SynchronizeProcess
// will call Match for each new executable mapping, and Attach when a match is found
// for a PID that has not yet been attached. Detach is called on process exit.
func (pm *ProcessManager) RegisterProbeAttacher(a ProbeAttacher) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.probeAttachers = append(pm.probeAttachers, a)
}
