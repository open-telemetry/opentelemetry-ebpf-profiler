//go:build !linux
// +build !linux

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracer

import (
	"fmt"
	"runtime"
)

// ProbeBPFSyscall checks if the syscall EBPF is available on the system.
func ProbeBPFSyscall() error {
	return fmt.Errorf("eBPF is not available on your system %s", runtime.GOOS)
}

// ProbeTracepoint checks if tracepoints are available on the system.
func ProbeTracepoint() error {
	return fmt.Errorf("tracepoints are not available on your system %s", runtime.GOOS)
}

// GetCurrentKernelVersion returns an error for OS other than linux.
func GetCurrentKernelVersion() (_, _, _ uint32, err error) {
	return 0, 0, 0, fmt.Errorf("kernel version detection is not supported on %s",
		runtime.GOOS)
}
