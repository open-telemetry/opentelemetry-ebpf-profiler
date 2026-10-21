// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package times // import "go.opentelemetry.io/ebpf-profiler/times"

import "golang.org/x/sys/unix"

// GetKTime gets the current time in the same nanosecond format as the
// bpf_ktime_get_boot_ns() eBPF call.
//
// This is a real syscall: the Go runtime only has a vDSO fast path for
// CLOCK_MONOTONIC (runtime.nanotime) and offers nothing for CLOCK_BOOTTIME.
// Callers invoke this a few times per poll interval at most, so the cost is
// irrelevant.
func GetKTime() KTime {
	var ts unix.Timespec
	// clock_gettime(2) only fails for an invalid clock ID or an unmapped timespec
	// pointer. CLOCK_BOOTTIME exists on every kernel able to load the eBPF code
	// (it needs bpf_ktime_get_boot_ns), so the error is deliberately ignored rather
	// than handled with a panic or a fallback to a different clock.
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return KTime(ts.Nano())
}
