// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package times // import "go.opentelemetry.io/ebpf-profiler/times"

import "time"

// KTime stores a time value in nanoseconds on CLOCK_BOOTTIME, the clock used by the
// bpf_ktime_get_boot_ns() eBPF helper for trace timestamps. Unlike CLOCK_MONOTONIC it
// keeps advancing while the system is suspended, so timestamps taken before and after
// a suspend convert to the correct wall-clock time with a single boot-time offset.
type KTime int64

// Time converts the kernel timestamp into a Go time object.
func (t KTime) Time() time.Time {
	return time.Unix(0, t.UnixNano())
}

// UnixNano converts the kernel timestamp to nanoseconds since the epoch.
func (t KTime) UnixNano() int64 {
	return int64(t) + bootTimeUnixNano.Load()
}
