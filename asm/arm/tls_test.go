// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	aa "golang.org/x/arch/arm64/arm64asm"
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
			// rb_current_ec_noinline from statically linked Ruby 3.4.7.
			// GCC emits a hi12/lo12 ADD pair for local-exec TLS.
			name: "Ruby 3.4.7 static ARM64 with hi12/lo12 ADD pair",
			code: []byte{
				0x40, 0xd0, 0x3b, 0xd5, // MRS X0, TPIDR_EL0
				0x00, 0x00, 0x40, 0x91, // ADD X0, X0, #0x0, LSL #12
				0x00, 0xe0, 0x00, 0x91, // ADD X0, X0, #0x38
				0x00, 0x00, 0x40, 0xf9, // LDR X0, [X0]
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr: 0x1000,
			expected: 56,
		},
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
			name: "MRS followed only by zero shifted ADD",
			code: []byte{
				// MRS X0, TPIDR_EL0
				0x40, 0xd0, 0x3b, 0xd5,
				// ADD X0, X0, #0x0, LSL #12 (zero offset is not accepted)
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

func TestDecodeImmediatePostIndex(t *testing.T) {
	decodeOneMem := func(t *testing.T, code []byte) aa.MemImmediate {
		t.Helper()
		inst, err := aa.Decode(code)
		require.NoError(t, err)
		require.Equal(t, aa.LDR, inst.Op)
		mem, ok := inst.Args[1].(aa.MemImmediate)
		require.True(t, ok, "expected MemImmediate operand")
		return mem
	}

	testdata := []struct {
		name    string
		code    []byte
		wantVal int64
		wantOK  bool
	}{
		{
			// LDR X0, [X1], #8
			name:    "post-index positive offset",
			code:    []byte{0x20, 0x84, 0x40, 0xF8},
			wantVal: 8,
			wantOK:  true,
		},
		{
			// LDR X0, [X1, #32]
			name:    "offset mode",
			code:    []byte{0x20, 0x10, 0x40, 0xF9},
			wantVal: 32,
			wantOK:  true,
		},
		{
			// LDR X0, [X1, #16]!
			name:    "pre-index mode",
			code:    []byte{0x20, 0x0C, 0x41, 0xF8},
			wantVal: 16,
			wantOK:  true,
		},
	}

	for _, td := range testdata {
		t.Run(td.name, func(t *testing.T) {
			mem := decodeOneMem(t, td.code)
			// Must not panic.
			val, ok := DecodeImmediate(mem)
			require.Equal(t, td.wantOK, ok)
			if td.wantOK {
				assert.Equal(t, td.wantVal, val)
			}
		})
	}
}

func TestExtractTLSOffsetPostIndexLDR(t *testing.T) {
	code := []byte{
		0x41, 0xd0, 0x3b, 0xd5, // MRS X1, TPIDR_EL0
		0x20, 0x84, 0x40, 0xf8, // LDR X0, [X1], #8  (post-index — must not panic)
		0xc0, 0x03, 0x5f, 0xd6, // RET
	}
	offset, err := ExtractTLSOffset(code, 0x1000, nil)
	require.NoError(t, err)
	assert.Equal(t, int32(8), offset)
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
			// The descriptor resolver is called through BLR with the
			// descriptor in X0 and returns the TP-relative offset in X0.
			name: "Python 3.13 shared ARM64 TLS descriptor",
			code: []byte{
				0x3f, 0x23, 0x03, 0xd5, // PACIASP
				0x41, 0xd0, 0x3b, 0xd5, // MRS X1, TPIDR_EL0
				0xfd, 0x7b, 0xbf, 0xa9, // STP X29, X30, [SP, #-16]!
				0xfd, 0x03, 0x00, 0x91, // MOV X29, SP
				0x40, 0x1f, 0x00, 0xf0, // ADRP X0, 0x6d1000
				0x02, 0x68, 0x40, 0xf9, // LDR X2, [X0, #208]
				0x00, 0x40, 0x03, 0x91, // ADD X0, X0, #0xd0
				0x40, 0x00, 0x3f, 0xd6, // BLR X2
				0x20, 0x68, 0x60, 0xf8, // LDR X0, [X1, X0]
				0xfd, 0x7b, 0xc1, 0xa8, // LDP X29, X30, [SP], #16
				0xbf, 0x23, 0x03, 0xd5, // AUTIASP
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr: 0x2e6444,
			slot:     0x6d10d0, // ADRP page 0x6d1000 + 0xd0
		},
		{
			// Clang emits a descriptor for the module's TLS block
			// (_TLS_MODULE_BASE_) for a dso_local variable, and adds the
			// variable's offset with a :dtprel_hi12:/:dtprel_lo12_nc: ADD pair.
			name: "ARM64 TLS descriptor for module base with hi12/lo12 ADD pair",
			code: []byte{
				0x80, 0x00, 0x00, 0x90, // ADRP X0, 0x11000
				0x01, 0x08, 0x40, 0xf9, // LDR X1, [X0, #16]
				0x00, 0x40, 0x00, 0x91, // ADD X0, X0, #0x10
				0x20, 0x00, 0x3f, 0xd6, // BLR X1
				0x00, 0x04, 0x40, 0x91, // ADD X0, X0, #0x1, LSL #12
				0x00, 0x20, 0x00, 0x91, // ADD X0, X0, #0x8
				0x48, 0xd0, 0x3b, 0xd5, // MRS X8, TPIDR_EL0
				0x00, 0x69, 0x60, 0xf8, // LDR X0, [X8, X0]
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr: 0x1000,
			slot:     0x11010, // ADRP page 0x11000 + 0x10
			disp:     0x1008,  // 0x1000 from the LSL #12 ADD + 0x8
		},
		{
			// The returned offset is copied to another register before the
			// ADD pair, so the displacement cannot be followed.
			name: "ARM64 TLS descriptor with offset copied after the call",
			code: []byte{
				0x80, 0x00, 0x00, 0x90, // ADRP X0, 0x11000
				0x01, 0x08, 0x40, 0xf9, // LDR X1, [X0, #16]
				0x00, 0x40, 0x00, 0x91, // ADD X0, X0, #0x10
				0x20, 0x00, 0x3f, 0xd6, // BLR X1
				0xe2, 0x03, 0x00, 0xaa, // MOV X2, X0
				0x42, 0x04, 0x40, 0x91, // ADD X2, X2, #0x1, LSL #12
				0x42, 0x20, 0x00, 0x91, // ADD X2, X2, #0x8
				0x48, 0xd0, 0x3b, 0xd5, // MRS X8, TPIDR_EL0
				0x00, 0x69, 0x62, 0xf8, // LDR X0, [X8, X2]
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr:      0x1000,
			expectedError: "could not follow the offset returned by the TLS descriptor call",
		},
		{
			// The returned offset is overwritten by a reload before it is used.
			name: "ARM64 TLS descriptor with offset overwritten after the call",
			code: []byte{
				0x80, 0x00, 0x00, 0x90, // ADRP X0, 0x11000
				0x01, 0x08, 0x40, 0xf9, // LDR X1, [X0, #16]
				0x00, 0x40, 0x00, 0x91, // ADD X0, X0, #0x10
				0x20, 0x00, 0x3f, 0xd6, // BLR X1
				0xe0, 0x07, 0x40, 0xf9, // LDR X0, [SP, #8]
				0x48, 0xd0, 0x3b, 0xd5, // MRS X8, TPIDR_EL0
				0x00, 0x69, 0x60, 0xf8, // LDR X0, [X8, X0]
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr:      0x1000,
			expectedError: "could not follow the offset returned by the TLS descriptor call",
		},
		{
			// The GOT slot holds the TP-relative offset, filled in by the
			// dynamic loader, and is added to TPIDR_EL0 by a register LDR.
			name: "ARM64 initial-exec GOT slot with register LDR",
			code: []byte{
				0xe0, 0x00, 0x00, 0xf0, // ADRP X0, 0x1f000
				0x00, 0xe0, 0x47, 0xf9, // LDR X0, [X0, #4032]
				0x41, 0xd0, 0x3b, 0xd5, // MRS X1, TPIDR_EL0
				0x20, 0x68, 0x60, 0xf8, // LDR X0, [X1, X0]
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr: 0x5c0,
			slot:     0x1ffc0, // ADRP page 0x1f000 + 0xfc0
		},
		{
			// As above, but the variable's address is formed by a register
			// ADD before it is loaded.
			name: "ARM64 initial-exec GOT slot with register ADD",
			code: []byte{
				0xe0, 0x00, 0x00, 0xf0, // ADRP X0, 0x1f000
				0x00, 0xe0, 0x47, 0xf9, // LDR X0, [X0, #4032]
				0x41, 0xd0, 0x3b, 0xd5, // MRS X1, TPIDR_EL0
				0x20, 0x00, 0x00, 0x8b, // ADD X0, X1, X0
				0x00, 0x00, 0x40, 0xf9, // LDR X0, [X0]
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr: 0x5c0,
			slot:     0x1ffc0, // ADRP page 0x1f000 + 0xfc0
		},
		{
			// gcc -mtls-dialect=trad: __tls_get_addr returns the variable's
			// address, which is then loaded.
			name: "ARM64 general-dynamic __tls_get_addr call",
			code: []byte{
				0xfd, 0x7b, 0xbf, 0xa9, // STP X29, X30, [SP, #-16]!
				0xfd, 0x03, 0x00, 0x91, // MOV X29, SP
				0xe0, 0x00, 0x00, 0xf0, // ADRP X0, 0x1f000
				0x00, 0x40, 0x3f, 0x91, // ADD X0, X0, #0xfd0
				0xb0, 0xff, 0xff, 0x97, // BL __tls_get_addr
				0x1f, 0x20, 0x03, 0xd5, // NOP
				0x00, 0x00, 0x40, 0xf9, // LDR X0, [X0]
				0xfd, 0x7b, 0xc1, 0xa8, // LDP X29, X30, [SP], #16
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr: 0x700,
			slot:     0x1ffd0, // ADRP page 0x1f000 + 0xfd0
		},
		{
			name: "ARM64 __tls_get_addr call with displacement",
			code: []byte{
				0xe0, 0x00, 0x00, 0xf0, // ADRP X0, 0x1f000
				0x00, 0x40, 0x3f, 0x91, // ADD X0, X0, #0xfd0
				0xb0, 0xff, 0xff, 0x97, // BL __tls_get_addr
				0x00, 0x20, 0x00, 0x91, // ADD X0, X0, #0x8
				0x00, 0x04, 0x40, 0xf9, // LDR X0, [X0, #8]
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr: 0x700,
			slot:     0x1ffd0, // ADRP page 0x1f000 + 0xfd0
			disp:     0x10,
		},
		{
			name: "ARM64 __tls_get_addr call with address overwritten",
			code: []byte{
				0xe0, 0x00, 0x00, 0xf0, // ADRP X0, 0x1f000
				0x00, 0x40, 0x3f, 0x91, // ADD X0, X0, #0xfd0
				0xb0, 0xff, 0xff, 0x97, // BL __tls_get_addr
				0xe0, 0x07, 0x40, 0xf9, // LDR X0, [SP, #8]
				0x00, 0x00, 0x40, 0xf9, // LDR X0, [X0]
				0xc0, 0x03, 0x5f, 0xd6, // RET
			},
			baseAddr:      0x700,
			expectedError: "could not follow the address returned by the TLS call",
		},
		{
			// Local-exec adds a fixed offset to TPIDR_EL0 without a GOT slot;
			// see TestExtractTLSOffset.
			name: "no GOT-based access found (local-exec)",
			code: []byte{
				0x40, 0xd0, 0x3b, 0xd5, // MRS X0, TPIDR_EL0
				0x00, 0x40, 0x00, 0x91, // ADD X0, X0, #0x10
				0x00, 0x00, 0x40, 0xf9, // LDR X0, [X0]
				0xc0, 0x03, 0x5f, 0xd6, // RET
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
