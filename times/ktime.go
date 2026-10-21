// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package times // import "go.opentelemetry.io/ebpf-profiler/times"

import (
	"time"

	"golang.org/x/sys/unix"
)

// KTime stores a time value in nanoseconds on CLOCK_BOOTTIME, the clock used by the
// bpf_ktime_get_boot_ns() eBPF helper for trace timestamps. Unlike CLOCK_MONOTONIC it
// keeps advancing while the system is suspended, so timestamps taken before and after
// a suspend convert to the correct wall-clock time with a single boot-time offset.
type KTime int64

// GetKTime gets the current time in the same nanosecond format as the
// bpf_ktime_get_boot_ns() eBPF call.
//
// This is a syscall: the Go runtime only has a vDSO fast path for
// CLOCK_MONOTONIC (runtime.nanotime) and offers nothing for CLOCK_BOOTTIME.
// Callers invoke this a few times per poll interval at most, so the cost is
// irrelevant.
func GetKTime() KTime {
	var ts unix.Timespec
	// clock_gettime(2) only fails for an invalid clock ID (can't happen on any kernel
	// we execute on) or an unmapped timespec pointer. CLOCK_BOOTTIME exists on every
	// kernel we execute on.
	_ = unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts)
	return KTime(ts.Nano())
}

// Time converts the kernel timestamp into a Go time object.
func (t KTime) Time() time.Time {
	return time.Unix(0, t.UnixNano())
}

// UnixNano converts the kernel timestamp to nanoseconds since the epoch.
func (t KTime) UnixNano() int64 {
	return int64(t) + bootTimeUnixNano.Load()
}
