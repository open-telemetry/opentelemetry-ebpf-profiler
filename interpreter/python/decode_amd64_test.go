//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestAmd64DecodeStub(t *testing.T) {
	testdata := []struct {
		name     string
		code     []byte
		mem      uint64
		rip      uint64
		expected uint64
	}{
		{
			name: "cpython 3.12 ",
			code: []byte{

				0xF3, 0x0F, 0x1E, 0xFA, // endbr64
				0x53,                               // push    rbx
				0x48, 0x8D, 0x1D, 0x1C, 0x42, 0x37, // lea     rbx, __TMC_END__.autoTSSkey
				0x00,             //
				0x48, 0x89, 0xDF, // mov     rdi, rbx
				0xE8, 0x8C, 0x83, 0x01, 0x00, // call    PyThread_tss_is_created
				0x85, 0xC0, // test    eax, eax
				0x74, 0x10, // jz      short loc_2F1928
				0x48, 0x89, 0xDF, // mov     rdi, rbx
				0x5B, // pop     rbx
			},
			mem:      0, // not unused
			rip:      0x2F1900,
			expected: 0x665B28,
		},
		{
			name: "cpython 3.10 PyGILState_GetThisThreadState",
			code: []byte{
				0xF3, 0x0F, 0x1E, 0xFA, //     endbr64
				0x48, 0x8B, 0x05, 0xB5, 0x2D, //     mov     rax, cs:runtime << mem
				0x18, 0x00, //
				0x48, 0x83, 0xB8, 0x40, 0x02, //     cmp     qword ptr [rax+240h], 0
				0x00, 0x00, 0x00, //
				0x74, 0x13, //     jz      short loc_209F98
				0x48, 0x8D, 0xB8, 0x48, 0x02, //     lea     rdi, [rax+248h] ; key
				0x00, 0x00, //
				0xE9, 0xFF, 0xF9, 0xE5, 0xFF, //     jmp     _PyThread_tss_get
			},
			mem:      0x3C1680,
			rip:      0x209F70,
			expected: 0x3C18C8,
		},
		{
			name: "cpython 3.11.2 PyGILState_GetThisThreadState google/cloud-sdk:502.0.0-slim",
			code: []byte{
				0x48, 0x83, 0x3D, 0x00, 0x47, // cmp     cs:qword_A5C968, 0
				0x56, 0x00, 0x00, //
				0x0F, 0x84, 0xEF, 0xC1, 0xF2, // jz      loc_42445D
				0xFF,                         //
				0x8B, 0x3D, 0x00, 0x47, 0x56, // mov     edi, cs:dword_A5C974
				0x00,                         //
				0xE9, 0x77, 0x84, 0xF2, 0xFF, // jmp     _pthread_getspecific
			},
			mem:      0, // not used
			rip:      0x4F8260,
			expected: 0xA5C974,
		},
		{
			name: "gcloud-sdk 515.0.0 3.12 bundled",
			code: []byte{
				0x53,                         // push    rbx
				0xBB, 0x08, 0x06, 0x00, 0x00, // mov     ebx, 608h
				0x48, 0x03, 0x1D, 0xBB, 0x10, 0x1A, 0x01, // add     rbx, cs:_PyRuntime_ptr << mem
				0x48, 0x89, 0xDF, // mov     rdi, rbx
				0xE8, 0x6B, 0x81, 0xE5, 0xFF, // call    _PyThread_tss_is_created
				0x85, 0xC0, // test    eax, eax
				0x74, 0x09, // jz      short loc_3C89E2
				0x48, 0x89, 0xDF, // mov     rdi, rbx
				0x5B,                         // pop     rbx
				0xE9, 0x3E, 0xA3, 0xE5, 0xFF, // jmp     _PyThread_tss_get
			},
			mem:      0x16905C0,
			rip:      0x3C89C0,
			expected: 0x16905C0 + 0x608,
		},
		{
			name: "gcloud-sdk 502 3.11 bundled",
			code: []byte{
				0x48, 0x8B, 0x05, 0x61, 0x9D, 0x12, 0x01, // mov     rax, cs:_PyRuntime_ptr
				0x48, 0x83, 0xB8, 0x48, 0x02, 0x00, 0x00, 0x00, // cmp     qword ptr [rax+248h], 0
				0x74, 0x11, // jz      short loc_377D42
				0xBF, 0x50, 0x02, 0x00, 0x00, // mov     edi, 250h
				0x48, 0x03, 0x3D, 0x4B, 0x9D, 0x12, 0x01, // add     rdi, cs:_PyRuntime_ptr << mem
				0xE9, 0x5E, 0x6E, 0xE9, 0xFF, // jmp     _PyThread_tss_get
			},
			mem:      0x15D36F0,
			rip:      0x77D20,
			expected: 0x15D36F0 + 0x250,
		},
	}

	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			val := decodeStubArgumentWrapperX64(
				td.code,
				libpf.SymbolValue(td.rip),
				libpf.SymbolValue(td.mem),
			)
			assert.Equal(t, libpf.SymbolValue(td.expected), val)
		})
	}
}
