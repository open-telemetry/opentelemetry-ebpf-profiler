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

// NewProcessVirtualMemory returns RemoteMemory for reading another process's
// virtual memory. When procFsPath is "/" or empty (host-native case), it uses
// the process_vm_readv(2) syscall. For any other non-empty path it reads from
// <rootFsPath>/proc/<pid>/mem, which is used when the host procfs is mounted at
// a non-standard location inside a container.
func NewProcessVirtualMemory(pid libpf.PID, rootFsPath string) RemoteMemory {
	if rootFsPath == "/" || len(rootFsPath) == 0 {
		return RemoteMemory{ReaderAt: ProcessVirtualMemory{pid: pid}}
	}
	return RemoteMemory{ReaderAt: ProcVirtualMemory{pid: pid, rootFsPath: rootFsPath}}
}

// ProcessVirtualMemory implements ReaderAt by reading /proc/<pid>/mem or using
// the process_vm_readv syscall.
type ProcessVirtualMemory struct {
	pid libpf.PID
}

func (vm ProcessVirtualMemory) ReadAt(p []byte, off int64) (int, error) {
	numBytesWanted := len(p)
	if numBytesWanted == 0 {
		return 0, nil
	}
	localIov := []unix.Iovec{{Base: &p[0], Len: uint64(numBytesWanted)}}
	remoteIov := []unix.RemoteIovec{{Base: uintptr(off), Len: numBytesWanted}}
	numBytesRead, err := unix.ProcessVMReadv(int(vm.pid), localIov, remoteIov, 0)
	if err != nil {
		err = fmt.Errorf("failed to read PID %v at 0x%x: %w", vm.pid, off, err)
	} else if numBytesRead != numBytesWanted {
		err = fmt.Errorf("failed to read PID %v at 0x%x: got only %d of %d",
			vm.pid, off, numBytesRead, numBytesWanted)
	}
	return numBytesRead, err
}

// ProcVirtualMemory implements ReaderAt by reading /proc/<pid>/mem
type ProcVirtualMemory struct {
	pid        libpf.PID
	rootFsPath string
}

func (vm ProcVirtualMemory) ReadAt(p []byte, off int64) (int, error) {
	// Use /proc/<pid>/mem instead of process_vm_readv. process_vm_readv resolves
	// the target PID in the caller's PID namespace, so it fails with ESRCH when
	// the profiler runs in a container without hostPID:true even though the host
	// /proc is mounted. /proc/<pid>/mem is looked up by inode and works across
	// PID namespace boundaries as long as the host procfs is mounted and the
	// caller has ptrace permission (CAP_SYS_PTRACE).
	f, err := os.Open(path.Join(vm.rootFsPath, fmt.Sprintf("proc/%d/mem", vm.pid)))
	if err != nil {
		return 0, fmt.Errorf("failed to open %s/proc/%v/mem: %w", vm.rootFsPath, vm.pid, err)
	}
	defer f.Close()

	n, err := f.ReadAt(p, off)
	if err != nil {
		return n, fmt.Errorf("failed to read PID %v at 0x%x: %w", vm.pid, off, err)
	}
	return n, nil
}
