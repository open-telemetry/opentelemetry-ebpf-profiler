// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	"go/version"

	"go.opentelemetry.io/ebpf-profiler/support"
)

// Offsets come from DWARF debug information, use tools/gooffsets to extract them.
// However since DWARF information can be stripped we record them here.
// TODO: Should we look for DWARF information to support new versions
// automatically when available?
func getOffsets(vers string) support.GoLabelsOffsets {
	offsets := support.GoLabelsOffsets{
		// https://github.com/golang/go/blob/80e2e474b8d9124d03b744f/src/runtime/runtime2.go#L410
		M_offset: 48,
		// https://github.com/golang/go/blob/80e2e474b8d9124d03b744f/src/runtime/runtime2.go#L541
		Curg: 192,
		// https://github.com/golang/go/blob/80e2e474b8d9124d03b744f/src/runtime/runtime2.go#L483
		Labels: 0,
		// https://github.com/golang/go/blob/6885bad7dd86880be6929c0/src/runtime/map.go#L112
		Hmap_count: 0,
		// https://github.com/golang/go/blob/6885bad7dd86880be6929c0/src/runtime/map.go#L114
		Hmap_log2_bucket_count: 0,
		// https://github.com/golang/go/blob/6885bad7dd86880be6929c0/src/runtime/map.go#L118
		Hmap_buckets: 0,
		// g.sched is a gobuf struct immediately following g.m (offset 48 + 8 = 56).
		// gobuf.sp is the first field (offset 0 in gobuf), gobuf.pc is the second (offset 8).
		// https://github.com/golang/go/blob/80e2e474b8d9124d03b744f4e2da099a4eec5957/src/runtime/runtime2.go#L311
		Sched_sp: 56,
		Sched_pc: 64,
		// gobuf.bp is at offset 48 within gobuf in go1.24 and earlier. In go1.25 and later,
		// it is at offset 40 because of ret field removal. (offset 56 + 48 = 104)
		// go1.25: https://github.com/golang/go/blob/6e676ab2b809d46623acb5988248d95d1eb7939c/src/runtime/runtime2.go#L315
		Sched_bp: 104,
	}

	// Version enforcement takes place in the Loader function.
	if version.Compare(vers, "go1.26") >= 0 {
		offsets.Curg = 184
		offsets.Labels = 352
		offsets.Sched_bp = 96
		return offsets
	} else if version.Compare(vers, "go1.25") >= 0 {
		offsets.Curg = 184
		offsets.Labels = 344
		offsets.Sched_bp = 96
		return offsets
	} else if version.Compare(vers, "go1.24") >= 0 {
		offsets.Labels = 352
		return offsets
	}

	// These are the same for all versions but we have to leave them zero for 1.24+ detection.
	offsets.Hmap_log2_bucket_count = 9
	offsets.Hmap_buckets = 16
	if version.Compare(vers, "go1.23") >= 0 {
		offsets.Labels = 352
	} else if version.Compare(vers, "go1.21") >= 0 {
		offsets.Labels = 344
	} else if version.Compare(vers, "go1.17") >= 0 {
		offsets.Labels = 360
	} else {
		offsets.Labels = 344
	}
	return offsets
}
