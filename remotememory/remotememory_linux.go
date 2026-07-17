//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package remotememory // import "go.opentelemetry.io/ebpf-profiler/remotememory"

import (
	"fmt"
	"os"
)

func (vm ProcessVirtualMemory) ReadAt(p []byte, off int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	// Use /proc/<pid>/mem instead of process_vm_readv. process_vm_readv resolves
	// the target PID in the caller's PID namespace, so it fails with ESRCH when
	// the profiler runs in a container without hostPID:true even though the host
	// /proc is mounted. /proc/<pid>/mem is looked up by inode and works across
	// PID namespace boundaries as long as the host procfs is mounted and the
	// caller has ptrace permission (CAP_SYS_PTRACE).
	f, err := os.Open(fmt.Sprintf("%s/proc/%d/mem", vm.procFsPath, vm.pid))
	if err != nil {
		return 0, fmt.Errorf("failed to open /proc/%v/mem: %w", vm.pid, err)
	}
	defer f.Close()

	n, err := f.ReadAt(p, off)
	if err != nil {
		return n, fmt.Errorf("failed to read PID %v at 0x%x: %w", vm.pid, off, err)
	}
	return n, nil
}
