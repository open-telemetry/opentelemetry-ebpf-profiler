// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractTLSOffsetFromCodeARM64(t *testing.T) {
	testdata := []struct {
		name          string
		code          []byte
		baseAddr      uint64
		expected      int64
		expectedError string
	}{
		{
			name: "Python 3.13 ARM64 MRS followed by ADD",
			code: []byte{
				// MRS X0, TPIDR_EL0  (S3_3_C13_C0_2)
				0x40, 0xd0, 0x3b, 0xd5,
				// ADD X0, X0, #0x10
				0x00, 0x40, 0x00, 0x91,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x1000,
			expected: 16, // offset 0x10
		},
		{
			name: "Python 3.13 ARM64 MRS followed by LDR",
			code: []byte{
				// MRS X1, TPIDR_EL0
				0x41, 0xd0, 0x3b, 0xd5,
				// LDR X0, [X1, #0x20]
				0x20, 0x10, 0x40, 0xf9,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x2000,
			expected: 32, // offset 0x20
		},
		{
			name: "Python 3.13 ARM64 MRS with intermediate register",
			code: []byte{
				// MRS X2, TPIDR_EL0
				0x42, 0xd0, 0x3b, 0xd5,
				// ADD X3, X2, #0x50
				0x43, 0x40, 0x01, 0x91,
				// LDR X0, [X3, #0x8]
				0x60, 0x04, 0x40, 0xf9,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x3000,
			expected: 80, // offset 0x50 from ADD
		},
		{
			name: "Python 3.13 ARM64 MRS with multiple operations",
			code: []byte{
				// MRS X8, TPIDR_EL0
				0x48, 0xd0, 0x3b, 0xd5,
				// ADD X8, X8, #0x100
				0x08, 0x01, 0x04, 0x91,
				// LDR X0, [X8]
				0x00, 0x01, 0x40, 0xf9,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x4000,
			expected: 256, // offset 0x100
		},
		{
			name: "no MRS TPIDR_EL0 found",
			code: []byte{
				// MRS X0, SP_EL0 (different system register)
				0x00, 0x41, 0x38, 0xd5,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr:      0x1000,
			expectedError: "could not find MRS TPIDR_EL0 instruction",
		},
		{
			name: "MRS found but no matching ADD/LDR",
			code: []byte{
				// MRS X0, TPIDR_EL0
				0x40, 0xd0, 0x3b, 0xd5,
				// MOV X1, X0 (not ADD or LDR with offset)
				0x01, 0x00, 0x00, 0xaa,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr:      0x2000,
			expectedError: "found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset",
		},
		{
			name: "offset too large (out of valid range)",
			code: []byte{
				// MRS X0, TPIDR_EL0
				0x40, 0xd0, 0x3b, 0xd5,
				// ADD X0, X0, #0x1000 (too large, outside valid range < 0x1000)
				0x00, 0x00, 0x40, 0x91,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr:      0x3000,
			expectedError: "found MRS TPIDR_EL0 but no matching ADD/LDR with TLS offset",
		},
		{
			name:          "empty code",
			code:          []byte{},
			baseAddr:      0x1000,
			expectedError: "could not find MRS TPIDR_EL0 instruction",
		},
		{
			name: "LDR with immediate offset 0x18",
			code: []byte{
				// MRS X10, TPIDR_EL0
				0x4a, 0xd0, 0x3b, 0xd5,
				// LDR X9, [X10, #0x18]
				0x49, 0x0d, 0x40, 0xf9,
				// MOV X0, X9
				0xe0, 0x03, 0x09, 0xaa,
				// RET
				0xc0, 0x03, 0x5f, 0xd6,
			},
			baseAddr: 0x5000,
			expected: 24, // offset 0x18
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
