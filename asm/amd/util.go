// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import "slices"

var endbr64 = [4]byte{0xf3, 0x0f, 0x1e, 0xfa}

// On some binaries the function starts like this:
//
//	0x0000000000012860 <+0>:     f3 0f 1e fa     endbr64
//	0x0000000000012864 <+4>:     41 55   push   %r13
//
// This is some kind of stack smashing indirect jump protection, treat it as a nop,
// x86asm doesn't know how to handle it.
//
//nolint:gocritic
func SkipEndBranch(b []byte) ([]byte, int64) {
	if slices.Equal(b[0:4], endbr64[:]) {
		return b[4:], 4
	}
	return b, 0
}
