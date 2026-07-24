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
func NewProcessVirtualMemory(pid libpf.PID, rootFsPath string) (RemoteMemory, error) {
	if rootFsPath == "/" || len(rootFsPath) == 0 {
		return RemoteMemory{ReadAtCloser: ProcessVirtualMemory{pid: pid}}, nil
	}
	f, err := os.Open(path.Join(rootFsPath, fmt.Sprintf("proc/%d/mem", pid)))
	if err != nil {
		return RemoteMemory{}, fmt.Errorf("failed to open %s/proc/%v/mem: %w", rootFsPath, pid, err)
	}
	return RemoteMemory{ReadAtCloser: ProcVirtualMemory{pid: pid, file: f}}, nil
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

func (vm ProcessVirtualMemory) Close() error {
	return nil
}

// ProcVirtualMemory implements ReaderAt by reading /proc/<pid>/mem
type ProcVirtualMemory struct {
	pid  libpf.PID
	file *os.File
}

func (vm ProcVirtualMemory) ReadAt(p []byte, off int64) (int, error) {
	n, err := vm.file.ReadAt(p, off)
	if err != nil {
		return n, fmt.Errorf("failed to read PID %v at 0x%x: %w", vm.pid, off, err)
	}
	return n, nil
}

func (vm ProcVirtualMemory) Close() error {
	if vm.file != nil {
		return vm.file.Close()
	}
	return nil
}
