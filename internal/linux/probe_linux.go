//go:build linux
// +build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package linux // import "go.opentelemetry.io/ebpf-profiler/internal/linux"

import (
	"bytes"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	versionMajor uint32
	versionMinor uint32
	versionPatch uint32
	versionErr   error
	versionOnce  sync.Once
)

// ProbeBPFSyscall checks if the syscall EBPF is available on the system.
func ProbeBPFSyscall() error {
	_, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(unix.BPF_PROG_TYPE_UNSPEC), uintptr(0), 0)
	if errNo == unix.ENOSYS {
		return errors.New("eBPF syscall is not available on your system")
	}
	return nil
}

// GetCurrentKernelVersion returns the major, minor and patch version of the kernel of the host
// from the utsname struct.
func GetCurrentKernelVersion() (major, minor, patch uint32, err error) {
	versionOnce.Do(func() {
		var uname unix.Utsname
		if err := unix.Uname(&uname); err != nil {
			versionErr = err
		}
		_, _ = fmt.Fscanf(bytes.NewReader(uname.Release[:]), "%d.%d.%d", &versionMajor, &versionMinor, &versionPatch)
	})
	return versionMajor, versionMinor, versionPatch, versionErr
}
