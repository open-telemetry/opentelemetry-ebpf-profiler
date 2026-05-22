// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGoString(t *testing.T) {
	tests := map[string]struct {
		input     []byte
		wantValue string
		wantOK    bool
	}{
		"plain ascii": {
			input:     []byte("tenant\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
			wantValue: "tenant",
			wantOK:    true,
		},
		"valid multi-byte utf8": {
			input:     append([]byte("héllo"), 0),
			wantValue: "héllo",
			wantOK:    true,
		},
		"empty buffer": {
			input:     make([]byte, 16),
			wantValue: "",
			wantOK:    true,
		},
		"no nul terminator uses whole buffer": {
			input:     []byte("exactlysixteenb!"),
			wantValue: "exactlysixteenb!",
			wantOK:    true,
		},
		"stale bytes after nul are discarded": {
			// Models a short key written into a per-CPU slot that previously
			// held a longer key. Everything past the first NUL must be
			// dropped; otherwise this produces a garbage label name.
			input:     []byte("tier\x00equest-trace"),
			wantValue: "tier",
			wantOK:    true,
		},
		"invalid utf8 lone continuation byte": {
			input:  []byte{'b', 'a', 'd', 0x80, 0x00},
			wantOK: false,
		},
		"invalid utf8 truncated multi-byte rune": {
			// A 3-byte rune cut after its first byte, as fixed-width
			// truncation in the eBPF extractor can produce.
			input:  []byte{'x', 0xE2, 0x00},
			wantOK: false,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, ok := goString(tc.input)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, got.String())
		})
	}
}
