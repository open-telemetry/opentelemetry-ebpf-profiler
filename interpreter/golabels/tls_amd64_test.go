//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// mockPfelfFile implements minimal pfelf.File for testing
// Only VirtualMemory is used in extractOffsetFromBytes

type mockPfelfFile struct {
	mem map[int64][]byte
}

//nolint:gocritic
func (m *mockPfelfFile) VirtualMemory(addr int64, _ int, _ int) ([]byte, error) {
	if b, ok := m.mem[addr]; ok {
		return b, nil
	}
	return nil, errors.New("not found")
}

func TestExtractOffsetFromBytes(t *testing.T) {
	tests := map[string]struct {
		mockFileData   map[int64][]byte
		pc             uintptr
		ins            []byte
		expectedOffset int32
		err            error
	}{
		"UnexpectedASM": {
			mockFileData: make(map[int64][]byte),
			pc:           0x1000,
			ins: []byte{0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
				0x90, 0x90},
			err: errUnexpectedAsm,
		},
		"Direct": {
			mockFileData: make(map[int64][]byte),
			pc:           0x1000,
			ins: []byte{0x64, 0x48, 0x8b, 0x04, 0x25, 0xf8,
				0xff, 0xff, 0xff},
			expectedOffset: -8,
		},
		"Indirect": {
			mockFileData: map[int64][]byte{
				0x1000 + 7 + 0x10: {0xf8, 0xff, 0xff, 0xff},
			},
			pc: 0x1000,
			ins: []byte{0x48, 0x8b, 0x0d, 0x10, 0x00,
				0x00, 0x00, 0x64, 0x48, 0x8b, 0x01},
			expectedOffset: -8,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			f := &mockPfelfFile{
				mem: tc.mockFileData,
			}
			offset, err := extractOffsetFromBytes(f, tc.pc, tc.ins)
			require.Equal(t, tc.err, err)
			require.Equal(t, tc.expectedOffset, offset)
		})
	}
}
