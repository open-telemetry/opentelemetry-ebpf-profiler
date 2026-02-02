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
