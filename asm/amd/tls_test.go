// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractTLSOffset(t *testing.T) {
	testdata := []struct {
		name          string
		code          []byte
		baseAddr      uint64
		expected      int32
		expectedError string
	}{
		{
			// rb_current_ec_noinline from statically linked Ruby 4.0.
			name: "Ruby 4.0 static x86_64",
			code: []byte{
				0x64, 0x48, 0x8b, 0x04, 0x25, 0x88, 0xff, 0xff, 0xff, // mov rax, QWORD PTR fs:[0xffffffffffffff88]
				0xc3, // ret
			},
			baseAddr: 0x1000,
			expected: -120,
		},
		{
			// rb_current_ec_noinline from statically linked Ruby 3.4.7.
			name: "Ruby 3.4.7 static x86_64",
			code: []byte{
				0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff, // mov rax, QWORD PTR fs:[0xfffffffffffffff8]
				0xc3, // ret
			},
			baseAddr: 0x1000,
			expected: -8,
		},
		{
			name: "Python 3.13 x86_64 direct FS access with negative offset",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff, // mov rax, QWORD PTR fs:[0xfffffffffffffff8]
				0xc3, // ret
			},
			baseAddr: 0x1000,
			expected: -8, // 0xfffffffffffffff8 as signed int32 = -8
		},
		{
			name: "Python 3.13 x86_64 direct FS access with small positive offset",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x64, 0x48, 0x8b, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, // mov rax, QWORD PTR fs:[0x10]
				0xc3, // ret
			},
			baseAddr: 0x1000,
			expected: 16, // 0x10
		},
		{
			name: "Python 3.13 x86_64 FS access offset 0x20",
			code: []byte{
				0x64, 0x48, 0x8b, 0x04, 0x25, 0x20, 0x00, 0x00, 0x00, // mov rax, QWORD PTR fs:[0x20]
				0x48, 0x85, 0xc0, // test rax, rax
				0xc3, // ret
			},
			baseAddr: 0x2000,
			expected: 32, // 0x20
		},
		{
			name: "Python 3.13 x86_64 FS access offset -0x10",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x64, 0x48, 0x8b, 0x14, 0x25, 0xf0, 0xff, 0xff, 0xff, // mov rdx, QWORD PTR fs:[0xfffffffffffffff0]
				0x48, 0x89, 0xd0, // mov rax, rdx
				0xc3, // ret
			},
			baseAddr: 0x3000,
			expected: -16, // 0xfffffffffffffff0 as signed int32 = -16
		},
		{
			name: "no FS-relative MOV found",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x48, 0x8b, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, // mov rax, QWORD PTR [0x10] (no FS prefix)
				0xc3, // ret
			},
			baseAddr:      0x1000,
			expectedError: "could not find FS-relative MOV instruction",
		},
		{
			name: "offset out of range (too large)",
			code: []byte{
				0x64, 0x48, 0x8b, 0x04, 0x25, 0x00, 0x20, 0x00, 0x00, // mov rax, QWORD PTR fs:[0x2000]
				0xc3, // ret
			},
			baseAddr:      0x1000,
			expectedError: "could not find valid FS-relative MOV instruction",
		},
		{
			name:          "empty code",
			code:          []byte{},
			baseAddr:      0x1000,
			expectedError: "could not find FS-relative MOV instruction",
		},
		{
			name: "multiple instructions before FS access",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x48, 0x83, 0xec, 0x08, // sub rsp, 8
				0x48, 0x89, 0x5c, 0x24, 0x00, // mov [rsp], rbx
				0x64, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, // mov rax, QWORD PTR fs:[0x8]
				0x48, 0x85, 0xc0, // test rax, rax
				0xc3, // ret
			},
			baseAddr: 0x5000,
			expected: 8,
		},
	}

	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			offset, err := ExtractTLSOffset(td.code, td.baseAddr, nil)
			if td.expectedError != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), td.expectedError)
			} else {
				require.NoError(t, err)
				assert.Equal(t, td.expected, offset)
			}
		})
	}
}

func TestExtractTLSSlot(t *testing.T) {
	testdata := []struct {
		name          string
		code          []byte
		baseAddr      uint64
		slot          uint64
		disp          int64
		expectedError string
	}{
		{
			// _PyThreadState_GetCurrent from Debian's libpython3.13.so.1.0.
			name: "Python 3.13 shared x86_64 local-dynamic via __tls_get_addr",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x48, 0x83, 0xec, 0x08, // sub rsp, 8
				0x48, 0x8d, 0x3d, 0x31, 0x8d, 0x3f, 0x00, // lea rdi, [rip+0x3f8d31]
				0xe8, 0x9c, 0xb1, 0xd9, 0xff, // call __tls_get_addr@plt
				0x48, 0x8b, 0x80, 0x08, 0x00, 0x00, 0x00, // mov rax, [rax+0x8]
				0x48, 0x83, 0xc4, 0x08, // add rsp, 8
				0xc3, // ret
			},
			baseAddr: 0x2fdad0,
			slot:     0x6f6810, // 0x2fdadf (RIP after lea) + 0x3f8d31
			disp:     8,        // offset within the module's TLS block
		},
		{
			// As above, but built with -fno-plt: __tls_get_addr is called
			// through its GOT entry, and the tls_index must still come from RDI.
			name: "x86_64 local-dynamic via __tls_get_addr with -fno-plt",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x48, 0x83, 0xec, 0x08, // sub rsp, 8
				0x48, 0x8d, 0x3d, 0x31, 0x8d, 0x3f, 0x00, // lea rdi, [rip+0x3f8d31]
				0xff, 0x15, 0x00, 0x10, 0x00, 0x00, // call [rip+0x1000]
				0x48, 0x8b, 0x80, 0x08, 0x00, 0x00, 0x00, // mov rax, [rax+0x8]
				0x48, 0x83, 0xc4, 0x08, // add rsp, 8
				0xc3, // ret
			},
			baseAddr: 0x2fdad0,
			slot:     0x6f6810, // 0x2fdadf (RIP after lea) + 0x3f8d31
			disp:     8,        // offset within the module's TLS block
		},
		{
			// The tls_index relocation carries the variable's offset, so the
			// block address returned by __tls_get_addr is used as is.
			name: "x86_64 general-dynamic via __tls_get_addr",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x48, 0x83, 0xec, 0x08, // sub rsp, 8
				0x66, 0x48, 0x8d, 0x3d, 0xa8, 0x2e, 0x00, 0x00, // data16 lea rdi, [rip+0x2ea8]
				0x66, 0x66, 0x48, 0xe8, 0x00, 0xff, 0xff, 0xff, // data16 data16 rex.W call __tls_get_addr@plt
				0x48, 0x8b, 0x00, // mov rax, [rax]
				0x48, 0x83, 0xc4, 0x08, // add rsp, 8
				0xc3, // ret
			},
			baseAddr: 0x1000,
			slot:     0x3eb8, // 0x1010 (RIP after lea) + 0x2ea8
		},
		{
			// The GOT slot holds the TP-relative offset, filled in by the
			// dynamic loader.
			name: "x86_64 initial-exec FS access through GOT slot",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x48, 0x8b, 0x05, 0xcd, 0x2e, 0x00, 0x00, // mov rax, [rip+0x2ecd]
				0x64, 0x48, 0x8b, 0x00, // mov rax, fs:[rax]
				0xc3, // ret
			},
			baseAddr: 0x1100,
			slot:     0x3fd8, // 0x110b (RIP after mov) + 0x2ecd
		},
		{
			// The descriptor resolver is called through the descriptor in RAX
			// and returns the TP-relative offset in RAX.
			name: "x86_64 TLS descriptor FS access",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x48, 0x83, 0xec, 0x08, // sub rsp, 8
				0x48, 0x8d, 0x05, 0xe1, 0x2e, 0x00, 0x00, // lea rax, [rip+0x2ee1]
				0xff, 0x10, // call [rax]
				0x64, 0x48, 0x8b, 0x00, // mov rax, fs:[rax]
				0x48, 0x83, 0xc4, 0x08, // add rsp, 8
				0xc3, // ret
			},
			baseAddr: 0x1110,
			slot:     0x4000, // 0x111f (RIP after lea) + 0x2ee1
		},
		{
			// The variable's offset is added to the block address returned by
			// __tls_get_addr with an LEA before the load.
			name: "x86_64 local-dynamic via __tls_get_addr with LEA",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x48, 0x83, 0xec, 0x08, // sub rsp, 8
				0x48, 0x8d, 0x3d, 0xf1, 0x2f, 0x00, 0x00, // lea rdi, [rip+0x2ff1]
				0xe8, 0x00, 0x00, 0x00, 0x00, // call __tls_get_addr@plt
				0x48, 0x8d, 0x40, 0x10, // lea rax, [rax+0x10]
				0x48, 0x8b, 0x00, // mov rax, [rax]
				0x48, 0x83, 0xc4, 0x08, // add rsp, 8
				0xc3, // ret
			},
			baseAddr: 0x1000,
			slot:     0x4000, // 0x100f (RIP after lea) + 0x2ff1
			disp:     0x10,   // from the LEA
		},
		{
			// A descriptor for the module's TLS block (_TLS_MODULE_BASE_),
			// with the variable's offset added to the returned TP-relative
			// offset.
			name: "x86_64 TLS descriptor for module base with ADD",
			code: []byte{
				0x48, 0x8d, 0x05, 0xf9, 0x2f, 0x00, 0x00, // lea rax, [rip+0x2ff9]
				0xff, 0x10, // call [rax]
				0x48, 0x83, 0xc0, 0x10, // add rax, 0x10
				0x64, 0x48, 0x8b, 0x00, // mov rax, fs:[rax]
				0xc3, // ret
			},
			baseAddr: 0x1000,
			slot:     0x4000, // 0x1007 (RIP after lea) + 0x2ff9
			disp:     0x10,   // from the ADD
		},
		{
			// RAX is overwritten after the call, so the following RAX-based
			// load is not the TLS access.
			name: "x86_64 __tls_get_addr result overwritten",
			code: []byte{
				0x48, 0x8d, 0x3d, 0xf9, 0x2f, 0x00, 0x00, // lea rdi, [rip+0x2ff9]
				0xe8, 0x00, 0x00, 0x00, 0x00, // call __tls_get_addr@plt
				0x48, 0x8b, 0x03, // mov rax, [rbx]
				0x48, 0x8b, 0x40, 0x08, // mov rax, [rax+0x8]
				0xc3, // ret
			},
			baseAddr:      0x1000,
			expectedError: "could not follow the result of the TLS call",
		},
		{
			// The result is copied to another register, so the displacement
			// cannot be followed.
			name: "x86_64 __tls_get_addr result copied",
			code: []byte{
				0x48, 0x8d, 0x3d, 0xf9, 0x2f, 0x00, 0x00, // lea rdi, [rip+0x2ff9]
				0xe8, 0x00, 0x00, 0x00, 0x00, // call __tls_get_addr@plt
				0x48, 0x89, 0xc2, // mov rdx, rax
				0x48, 0x8b, 0x42, 0x08, // mov rax, [rdx+0x8]
				0xc3, // ret
			},
			baseAddr:      0x1000,
			expectedError: "could not follow the result of the TLS call",
		},
		{
			// A descriptor returns a TP-relative offset, which must be read
			// FS-relative.
			name: "x86_64 TLS descriptor result read without FS",
			code: []byte{
				0x48, 0x8d, 0x05, 0xf9, 0x2f, 0x00, 0x00, // lea rax, [rip+0x2ff9]
				0xff, 0x10, // call [rax]
				0x48, 0x8b, 0x00, // mov rax, [rax]
				0xc3, // ret
			},
			baseAddr:      0x1000,
			expectedError: "unexpected access to TLS call result",
		},
		{
			// Local-exec uses a fixed FS offset without a GOT slot; see
			// TestExtractTLSOffset.
			name: "no GOT-based access found (local-exec)",
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8, 0xff, 0xff, 0xff, // mov rax, fs:[0xfffffffffffffff8]
				0xc3, // ret
			},
			baseAddr:      0x1000,
			expectedError: "could not find a GOT-based TLS access",
		},
	}

	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			slot, disp, err := ExtractTLSSlot(td.code, td.baseAddr)
			if td.expectedError != "" {
				require.ErrorContains(t, err, td.expectedError)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, td.slot, slot)
			assert.Equal(t, td.disp, disp)
		})
	}
}
