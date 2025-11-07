// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseProbe(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected *ProbeSpec
		wantErr  bool
		errMsg   string
	}{
		"kprobe_valid": {
			input: "kprobe:vfs_read",
			expected: &ProbeSpec{
				Type:     "kprobe",
				Symbol:   "vfs_read",
				ProgName: "kprobe__generic",
			},
			wantErr: false,
		},
		"kretprobe_valid": {
			input: "kretprobe:vfs_read",
			expected: &ProbeSpec{
				Type:     "kretprobe",
				Symbol:   "vfs_read",
				ProgName: "kprobe__generic",
			},
			wantErr: false,
		},
		"uprobe_valid": {
			input: "uprobe:/usr/lib/libc.so.6:malloc",
			expected: &ProbeSpec{
				Type:     "uprobe",
				Target:   "/usr/lib/libc.so.6",
				Symbol:   "malloc",
				ProgName: "uprobe__generic",
			},
			wantErr: false,
		},
		"uretprobe_valid": {
			input: "uretprobe:/usr/lib/libc.so.6:malloc",
			expected: &ProbeSpec{
				Type:     "uretprobe",
				Target:   "/usr/lib/libc.so.6",
				Symbol:   "malloc",
				ProgName: "uprobe__generic",
			},
			wantErr: false,
		},
		"kprobe_missing_symbol": {
			input:   "kprobe:",
			wantErr: true,
			errMsg:  "invalid format",
		},
		"kprobe_too_many_parts": {
			input:   "kprobe:symbol:extra",
			wantErr: true,
			errMsg:  "invalid format",
		},
		"kretprobe_missing_symbol": {
			input:   "kretprobe:",
			wantErr: true,
			errMsg:  "invalid format",
		},
		"uprobe_missing_symbol": {
			input:   "uprobe:/usr/lib/libc.so.6",
			wantErr: true,
			errMsg:  "invalid format",
		},
		"uprobe_empty_symbol": {
			input:   "uprobe:/usr/lib/libc.so.6:",
			wantErr: true,
			errMsg:  "invalid format",
		},
		"uprobe_missing_target": {
			input:   "uprobe::malloc",
			wantErr: false, // This will parse but target will be empty
			expected: &ProbeSpec{
				Type:     "uprobe",
				Target:   "",
				Symbol:   "malloc",
				ProgName: "uprobe__generic",
			},
		},
		"uretprobe_empty_symbol": {
			input:   "uretprobe:/bin/bash:",
			wantErr: true,
			errMsg:  "invalid format",
		},
		"unknown_probe_type": {
			input:   "tracepoint:syscalls:sys_enter_read",
			wantErr: true,
			errMsg:  "unknown probe type",
		},
		"empty_string": {
			input:   "",
			wantErr: true,
			errMsg:  "unknown probe type",
		},
		"no_colon": {
			input:   "kprobe",
			wantErr: true,
			errMsg:  "invalid format",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ParseProbe(tc.input)

			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.errMsg)
				assert.Nil(t, got)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, tc.expected.Type, got.Type)
				assert.Equal(t, tc.expected.Symbol, got.Symbol)
				if tc.expected.Target != "" {
					assert.Equal(t, tc.expected.Target, got.Target)
				}
				if tc.expected.ProgName != "" {
					assert.Equal(t, tc.expected.ProgName, got.ProgName)
				}
			}
		})
	}
}
