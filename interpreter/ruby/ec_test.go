// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/arm"
)

func TestExtractEcTLSOffset(t *testing.T) {
	tests := map[string]struct {
		machine elf.Machine
		code    []byte
		offset  int32
	}{
		// rb_current_ec_noinline for statically-linked ruby 4.0 on x86_64:
		//   mov %fs:0xffffffffffffff88,%rax
		//   ret
		"ruby 4.0 static / x86_64": {
			machine: elf.EM_X86_64,
			code: []byte{
				0x64, 0x48, 0x8b, 0x04, 0x25, 0x88, 0xff, 0xff, 0xff,
				0xc3,
			},
			offset: -120,
		},
		// rb_current_ec_noinline for statically-linked ruby 3.4.7 on x86_64:
		//   mov %fs:0xfffffffffffffff8,%rax
		//   ret
		"ruby 3.4.7 static / x86_64": {
			machine: elf.EM_X86_64,
			code: []byte{
				0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff,
				0xc3,
			},
			offset: -8,
		},
		// rb_current_ec_noinline for statically-linked ruby 3.4.7 on aarch64:
		//   mrs     x0, tpidr_el0
		//   add     x0, x0, #0x0, lsl #12
		//   add     x0, x0, #0x38
		//   ldr     x0, [x0]
		//   ret
		"ruby 3.4.7 static / aarch64": {
			machine: elf.EM_AARCH64,
			code: []byte{
				0x40, 0xd0, 0x3b, 0xd5, // mrs     x0, tpidr_el0
				0x00, 0x00, 0x40, 0x91, // add     x0, x0, #0x0, lsl #12
				0x00, 0xe0, 0x00, 0x91, // add     x0, x0, #0x38
				0x00, 0x00, 0x40, 0xf9, // ldr     x0, [x0]
				0xc0, 0x03, 0x5f, 0xd6, // ret
			},
			offset: 56,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var offset int32
			var err error
			switch tc.machine {
			case elf.EM_X86_64:
				offset, err = amd.ExtractTLSOffset(tc.code, 0, nil)
			case elf.EM_AARCH64:
				offset, err = arm.ExtractTLSOffset(tc.code, 0, nil)
			}
			require.NoError(t, err)
			assert.Equal(t, tc.offset, offset, "wrong ruby EC TLS offset")
		})
	}
}
