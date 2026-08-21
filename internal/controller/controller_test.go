// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package controller

import (
	"testing"
)

func TestCreateProbe(t *testing.T) {
	tests := []struct {
		name      string
		probeType string
		cfg       map[string]any
		wantErr   bool
	}{
		{
			name:      "kprobe valid",
			probeType: "kprobe",
			cfg:       map[string]any{"mode": "kprobe", "symbol": "vfs_open"},
		},
		{
			name:      "kprobe defaults mode when omitted",
			probeType: "kprobe",
			cfg:       map[string]any{"symbol": "vfs_read"},
		},
		{
			name:      "kprobe uprobe with target",
			probeType: "kprobe",
			cfg:       map[string]any{"mode": "uprobe", "symbol": "main", "target": "/usr/bin/myapp"},
		},
		{
			name:      "kprobe missing symbol",
			probeType: "kprobe",
			cfg:       map[string]any{"mode": "kprobe"},
			wantErr:   true,
		},
		{
			name:      "uprobe valid",
			probeType: "uprobe",
			cfg:       map[string]any{"target": "/usr/lib/libc.so.6", "symbol": "malloc"},
		},
		{
			name:      "uprobe missing target",
			probeType: "uprobe",
			cfg:       map[string]any{"symbol": "malloc"},
			wantErr:   true,
		},
		{
			name:      "uprobe missing symbol",
			probeType: "uprobe",
			cfg:       map[string]any{"target": "/usr/lib/libc.so.6"},
			wantErr:   true,
		},
		{
			name:      "uprobe unknown field",
			probeType: "uprobe",
			cfg:       map[string]any{"target": "/usr/lib/libc.so.6", "symbol": "malloc", "no_such_field": true},
			wantErr:   true,
		},
		{
			name:      "kprobe unknown mode",
			probeType: "kprobe",
			cfg:       map[string]any{"mode": "tracepoint", "symbol": "vfs_open"},
			wantErr:   true,
		},
		{
			name:      "unknown probe type",
			probeType: "tracepoint",
			cfg:       map[string]any{"symbol": "vfs_open"},
			wantErr:   true,
		},
		{
			name:      "confmap rejects unknown fields",
			probeType: "kprobe",
			cfg:       map[string]any{"symbol": "vfs_open", "no_such_field": true},
			wantErr:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := createProbe(tc.probeType, tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("createProbe(%q, %v): wantErr=%v, got err=%v", tc.probeType, tc.cfg, tc.wantErr, err)
				return
			}
			if !tc.wantErr && probe == nil {
				t.Errorf("createProbe(%q, %v): got nil probe without error", tc.probeType, tc.cfg)
			}
		})
	}
}
