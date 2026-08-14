// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// errProgramNotLoaded is returned by attach when no BPF program has been
// registered for the parsed probe's Kind. Reconcile treats this as a soft
// per-probe failure and continues with the rest.
var errProgramNotLoaded = errors.New("usdt: no BPF program registered for probe kind")

// attach creates one PID-scoped uprobe link for a single parsed probe.
//
// The kernel attaches uprobes by (inode, file_offset). We open the file via
// /proc/<pid>/map_files/<start>-<end>, which is a kernel-provided symlink
// resolving to exactly the inode the target process has mapped, regardless
// of mount namespace or whether the file has been replaced/deleted on disk.
func (m *Manager) attach(
	pid libpf.PID,
	mapping *process.RawMapping,
	p parsedProbe,
) (link.Link, error) {
	prog, ok := m.progs[p.Kind]
	if !ok {
		return nil, errProgramNotLoaded
	}

	path := fmt.Sprintf("/proc/%d/map_files/%x-%x",
		pid, mapping.Vaddr, mapping.Vaddr+mapping.Length)

	ex, err := link.OpenExecutable(path)
	if err != nil {
		return nil, fmt.Errorf("open executable %s: %w", path, err)
	}

	// Empty symbol: we attach by absolute file offset (UprobeOptions.Address),
	// not by symbol lookup. Cookie carries the ProbeKind so the BPF side can
	// dispatch via bpf_get_attach_cookie() if it ever needs to.
	lnk, err := ex.Uprobe("", prog, &link.UprobeOptions{
		PID:          int(pid),
		Address:      p.Location,
		RefCtrOffset: p.SemaphoreOffset,
		Cookie:       uint64(p.Kind),
	})
	if err != nil {
		return nil, fmt.Errorf("attach uprobe at %s+%#x: %w", path, p.Location, err)
	}
	return lnk, nil
}
