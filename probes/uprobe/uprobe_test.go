// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"testing"

	"github.com/cilium/ebpf/link"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg:  Config{Target: "/usr/lib/x86_64-linux-gnu/libc.so.6", Symbol: "malloc"},
		},
		{
			name:    "missing target",
			cfg:     Config{Symbol: "malloc"},
			wantErr: true,
		},
		{
			name:    "missing symbol",
			cfg:     Config{Target: "/usr/lib/x86_64-linux-gnu/libc.so.6"},
			wantErr: true,
		},
		{
			name:    "both missing",
			cfg:     Config{},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("New(%+v): wantErr=%v, got err=%v", tc.cfg, tc.wantErr, err)
				return
			}
			if !tc.wantErr && p == nil {
				t.Errorf("New(%+v): got nil probe without error", tc.cfg)
			}
		})
	}
}

func TestMatch(t *testing.T) {
	p := &probe{target: "/usr/lib/x86_64-linux-gnu/libc.so.6", symbol: "malloc"}

	tests := []struct {
		path string
		want bool
	}{
		{"/usr/lib/x86_64-linux-gnu/libc.so.6", true}, // exact match
		{"libc.so.6", true},                           // base name match
		{"/lib/x86_64-linux-gnu/libc.so.6", true},     // different directory, same base
		{"/usr/lib/x86_64-linux-gnu/libpthread.so.0", false},
		{"/usr/bin/python3", false},
		{"", false},
	}
	for _, tc := range tests {
		got := p.Match(tc.path)
		if got != tc.want {
			t.Errorf("Match(%q): want %v, got %v", tc.path, tc.want, got)
		}
	}
}

func TestDetachUnknownPID(t *testing.T) {
	p := &probe{
		target: "/usr/lib/x86_64-linux-gnu/libc.so.6",
		symbol: "malloc",
		links:  make(map[libpf.PID]link.Link),
	}
	// Detach on a PID that was never attached must not panic.
	p.Detach(42)
}
