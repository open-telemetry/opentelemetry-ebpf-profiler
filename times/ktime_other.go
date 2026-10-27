// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package times // import "go.opentelemetry.io/ebpf-profiler/times"

import "golang.org/x/sys/unix"

// GetKTime returns the closest available equivalent of Linux CLOCK_BOOTTIME.
// Non-Linux builds exist only to run the coredump test tool.
func GetKTime() KTime {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	return KTime(ts.Nano())
}
