/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package times

import (
	_ "unsafe" // required to use //go:linkname for runtime.nanotime
)

// KTime stores a time value, retrieved from a monotonic clock, in nanoseconds
type KTime int64

// GetKTime gets the current time in same nanosecond format as bpf_ktime_get_ns() eBPF call
// This relies runtime.nanotime to use CLOCK_MONOTONIC. If this changes, this needs to
// be adjusted accordingly. Using this internal is superior in performance, as it is able
// to use the vDSO to query the time without syscall.
//
//go:noescape
//go:linkname GetKTime runtime.nanotime
func GetKTime() KTime
