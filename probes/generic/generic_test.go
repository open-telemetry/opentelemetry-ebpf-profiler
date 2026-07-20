// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package generic

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

func TestParseProbeType(t *testing.T) {
	tests := []struct {
		input   string
		want    tracer.ProbeType
		wantErr bool
	}{
		{"kprobe", tracer.ProbeTypeKprobe, false},
		{"KPROBE", tracer.ProbeTypeKprobe, false},
		{"Kprobe", tracer.ProbeTypeKprobe, false},
		{"kretprobe", tracer.ProbeTypeKretprobe, false},
		{"KRETPROBE", tracer.ProbeTypeKretprobe, false},
		{"uprobe", tracer.ProbeTypeUprobe, false},
		{"UPROBE", tracer.ProbeTypeUprobe, false},
		{"uretprobe", tracer.ProbeTypeUretprobe, false},
		{"URETPROBE", tracer.ProbeTypeUretprobe, false},
		{"", 0, true},
		{"tracepoint", 0, true},
		{"kprobe ", 0, true},
	}
	for _, tc := range tests {
		got, err := parseProbeType(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseProbeType(%q): wantErr=%v, got err=%v", tc.input, tc.wantErr, err)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("parseProbeType(%q): want %v, got %v", tc.input, tc.want, got)
		}
	}
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		cfg     GenericConfig
		wantErr bool
	}{
		{
			name: "valid kprobe",
			cfg:  GenericConfig{Type: "kprobe", Symbol: "vfs_open"},
		},
		{
			name: "valid kretprobe",
			cfg:  GenericConfig{Type: "kretprobe", Symbol: "vfs_read"},
		},
		{
			name: "valid uprobe with target",
			cfg:  GenericConfig{Type: "uprobe", Symbol: "main", Target: "/usr/bin/myapp"},
		},
		{
			name: "valid uretprobe with target",
			cfg:  GenericConfig{Type: "uretprobe", Symbol: "main", Target: "/usr/bin/myapp"},
		},
		{
			name:    "missing type",
			cfg:     GenericConfig{Symbol: "vfs_open"},
			wantErr: true,
		},
		{
			name:    "missing symbol",
			cfg:     GenericConfig{Type: "kprobe"},
			wantErr: true,
		},
		{
			name:    "unknown type",
			cfg:     GenericConfig{Type: "tracepoint", Symbol: "vfs_open"},
			wantErr: true,
		},
		{
			name:    "uprobe missing target",
			cfg:     GenericConfig{Type: "uprobe", Symbol: "main"},
			wantErr: true,
		},
		{
			name:    "uretprobe missing target",
			cfg:     GenericConfig{Type: "uretprobe", Symbol: "main"},
			wantErr: true,
		},
		{
			name: "kprobe does not require target",
			cfg:  GenericConfig{Type: "kprobe", Symbol: "vfs_open", Target: ""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe, err := New(tc.cfg)
			if (err != nil) != tc.wantErr {
				t.Errorf("New(%+v): wantErr=%v, got err=%v", tc.cfg, tc.wantErr, err)
				return
			}
			if !tc.wantErr && probe == nil {
				t.Errorf("New(%+v): got nil probe without error", tc.cfg)
			}
		})
	}
}
