// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	fileIDLo      = 0x77efa716a912a492
	fileIDHi      = 0x17445787329fd29a
	addressOrLine = 0xe51c
)

func TestFrameID(t *testing.T) {
	var fileID = NewFileID(fileIDLo, fileIDHi)

	tests := []struct {
		name     string
		input    string
		expected FrameID
		bytes    []byte
		err      error
	}{
		{
			name:     "frame base64",
			input:    "d--nFqkSpJIXRFeHMp_SmgAAAAAAAOUc",
			expected: NewFrameID(fileID, addressOrLine),
			bytes: []byte{
				0x77, 0xef, 0xa7, 0x16, 0xa9, 0x12, 0xa4, 0x92, 0x17, 0x44, 0x57, 0x87,
				0x32, 0x9f, 0xd2, 0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe5, 0x1c,
			},
			err: nil,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			frameID, err := NewFrameIDFromString(test.input)
			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, frameID)

			// check if the roundtrip back to the input works
			assert.Equal(t, test.input, frameID.String())

			assert.Equal(t, test.bytes, frameID.Bytes())

			frameID, err = NewFrameIDFromBytes(frameID.Bytes())
			assert.Equal(t, test.err, err)
			assert.Equal(t, test.expected, frameID)

			ip := []byte(frameID.AsIP())
			bytes := frameID.Bytes()
			assert.Equal(t, bytes[:8], ip[:8])
			assert.Equal(t, bytes[16:], ip[8:])
		})
	}
}
