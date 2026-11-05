// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCommString(t *testing.T) {
	tests := map[string]struct {
		input     []byte
		wantValue string
	}{
		"plain ascii": {
			input:     []byte("tenant\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			wantValue: "tenant",
		},
		"valid multi-byte utf8": {
			input:     append([]byte("héllo"), 0),
			wantValue: "héllo",
		},
		"empty buffer": {
			input:     make([]byte, commLen),
			wantValue: "",
		},
		"no nul terminator uses whole buffer": {
			input:     []byte("exactlysixteenb!"),
			wantValue: "exactlysixteenb!",
		},
		"stale bytes after nul are discarded": {
			// Models a short string written into a per-CPU slot that previously
			// held a longer one. Everything past the first NUL must be dropped.
			input:     []byte("tier\x00equest-trace"),
			wantValue: "tier",
		},
		"invalid utf8 is passed through unvalidated": {
			// Comm is kernel-supplied and trusted as-is; validation happens only
			// for label strings.
			input:     []byte{'b', 'a', 'd', 0x80, 0x00},
			wantValue: "bad\x80",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var buffer [commLen]uint8
			copy(buffer[:], tc.input)

			got := NewComm(buffer)
			require.Equal(t, tc.wantValue, got.String())
		})
	}
}

func TestNewCommFromString(t *testing.T) {
	require.Equal(t, "comm", NewCommFromString("comm").String())
	require.Equal(t, "exactlysixteenb!", NewCommFromString("exactlysixteenb!tail").String())
}
