// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/metrics"
)

func TestCustomLabelValidatorValidateKey(t *testing.T) {
	tests := map[string]struct {
		input       []byte
		wantValue   string
		wantOK      bool
		wantDropped int64
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
		"empty buffer drops": {
			// An empty key cannot be grouped against, so reject.
			input:       make([]byte, 16),
			wantOK:      false,
			wantDropped: 1,
		},
		"stale bytes after nul are discarded": {
			input:     []byte("tier\x00equest-trace"),
			wantValue: "tier",
			wantOK:    true,
		},
		"mid-rune truncation drops the whole key": {
			// Keys are strict: a salvageable value-style prefix is not enough,
			// since dropping the trailing byte would silently change which key
			// samples are grouped under.
			input:       []byte{'o', 'k', 0xE2, 0x00},
			wantOK:      false,
			wantDropped: 1,
		},
		"trailing lone continuation byte drops": {
			input:       []byte{'a', 'b', 'c', 0x80, 0x00},
			wantOK:      false,
			wantDropped: 1,
		},
		"all-invalid bytes drop": {
			input:       []byte{0x80, 0x80, 0x00},
			wantOK:      false,
			wantDropped: 1,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var v customLabelValidator
			got, ok := v.validateKey(tc.input)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, string(got))
			require.Equal(t, tc.wantDropped, v.droppedInvalidName.Load())
		})
	}
}

func TestCustomLabelValidatorValidateValue(t *testing.T) {
	tests := map[string]struct {
		input       []byte
		wantValue   string
		wantOK      bool
		wantDropped int64
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
		"empty buffer is valid": {
			input:     make([]byte, 16),
			wantValue: "",
			wantOK:    true,
		},
		"stale bytes after nul are discarded": {
			input:     []byte("tier\x00equest-trace"),
			wantValue: "tier",
			wantOK:    true,
		},
		"mid-rune truncation salvages valid prefix": {
			// 3-byte rune (0xE2 0x98 0x83 = U+2603) cut after the first byte.
			// The valid "ok" prefix must be preserved.
			input:     []byte{'o', 'k', 0xE2, 0x00},
			wantValue: "ok",
			wantOK:    true,
		},
		"trailing lone continuation byte salvages valid prefix": {
			input:     []byte{'a', 'b', 'c', 0x80, 0x00},
			wantValue: "abc",
			wantOK:    true,
		},
		"all-invalid bytes drop": {
			input:       []byte{0x80, 0x80, 0x00},
			wantOK:      false,
			wantDropped: 1,
		},
		"single invalid byte drops": {
			input:       []byte{0xC0, 0x00},
			wantOK:      false,
			wantDropped: 1,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			var v customLabelValidator
			got, ok := v.validateValue(tc.input)
			require.Equal(t, tc.wantOK, ok)
			require.Equal(t, tc.wantValue, string(got))
			require.Equal(t, tc.wantDropped, v.droppedInvalidValue.Load())
		})
	}
}

func TestCustomLabelValidatorGetAndResetMetrics(t *testing.T) {
	var v customLabelValidator

	// Trigger two name drops and one value drop.
	v.validateKey([]byte{0xC0, 0})
	v.validateKey([]byte{0})
	v.validateValue([]byte{0xC0, 0})

	m := v.getAndResetMetrics()
	byID := map[metrics.MetricID]metrics.MetricValue{}
	for _, x := range m {
		byID[x.ID] = x.Value
	}
	require.Equal(t, metrics.MetricValue(2), byID[metrics.IDGoLabelsDroppedInvalidName])
	require.Equal(t, metrics.MetricValue(1), byID[metrics.IDGoLabelsDroppedInvalidValue])

	// Second call returns zeros — counters reset.
	m = v.getAndResetMetrics()
	for _, x := range m {
		require.Equal(t, metrics.MetricValue(0), x.Value, x.ID)
	}
}
