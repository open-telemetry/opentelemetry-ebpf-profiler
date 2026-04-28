// Copyright 2024 The Parca Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

// This package contains a series of helper functions that are useful for x86 disassembly.
package x86helpers // import "go.opentelemetry.io/ebpf-profiler/x86helpers"

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
