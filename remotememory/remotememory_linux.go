//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package remotememory // import "go.opentelemetry.io/ebpf-profiler/remotememory"

import (
	"fmt"
	"os"
	"path"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"golang.org/x/sys/unix"
)

func procMemRemoteMemory(rootFsPath string, pid libpf.PID) func(p []byte, off int64) (int, error) {
	return func(p []byte, off int64) (int, error) {
		// Use /proc/<pid>/mem instead of process_vm_readv. process_vm_readv resolves
		// the target PID in the caller's PID namespace, so it fails with ESRCH when
		// the profiler runs in a container without hostPID:true even though the host
		// /proc is mounted. /proc/<pid>/mem is looked up by inode and works across
		// PID namespace boundaries as long as the host procfs is mounted and the
		// caller has ptrace permission (CAP_SYS_PTRACE).
		f, err := os.Open(path.Join(rootFsPath, fmt.Sprintf("proc/%d/mem", pid)))
		if err != nil {
			return 0, fmt.Errorf("failed to open %s/proc/%v/mem: %w", rootFsPath, pid, err)
		}
		defer f.Close()

		n, err := f.ReadAt(p, off)
		if err != nil {
			return n, fmt.Errorf("failed to read PID %v at 0x%x: %w", pid, off, err)
		}
		return n, nil
	}
}

func processVMRemoteMemory(pid libpf.PID) func(p []byte, off int64) (int, error) {
	return func(p []byte, off int64) (int, error) {
		numBytesWanted := len(p)
		if numBytesWanted == 0 {
			return 0, nil
		}
		localIov := []unix.Iovec{{Base: &p[0], Len: uint64(numBytesWanted)}}
		remoteIov := []unix.RemoteIovec{{Base: uintptr(off), Len: numBytesWanted}}
		numBytesRead, err := unix.ProcessVMReadv(int(pid), localIov, remoteIov, 0)
		if err != nil {
			err = fmt.Errorf("failed to read PID %v at 0x%x: %w", pid, off, err)
		} else if numBytesRead != numBytesWanted {
			err = fmt.Errorf("failed to read PID %v at 0x%x: got only %d of %d",
				pid, off, numBytesRead, numBytesWanted)
		}
		return numBytesRead, err
	}
}
