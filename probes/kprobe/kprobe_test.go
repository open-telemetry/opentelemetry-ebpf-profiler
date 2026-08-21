// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kprobe

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

func TestParseProbeMode(t *testing.T) {
	tests := []struct {
		input   string
		want    tracer.ProbeMode
		wantErr bool
	}{
		{"kprobe", tracer.ProbeModeKprobe, false},
		{"KPROBE", tracer.ProbeModeKprobe, false},
		{"Kprobe", tracer.ProbeModeKprobe, false},
		{"kretprobe", tracer.ProbeModeKretprobe, false},
		{"KRETPROBE", tracer.ProbeModeKretprobe, false},
		{"uprobe", tracer.ProbeModeUprobe, false},
		{"UPROBE", tracer.ProbeModeUprobe, false},
		{"uretprobe", tracer.ProbeModeUretprobe, false},
		{"URETPROBE", tracer.ProbeModeUretprobe, false},
		{"", 0, true},
		{"tracepoint", 0, true},
		{"kprobe ", 0, true},
	}
	for _, tc := range tests {
		got, err := parseProbeMode(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("parseProbeMode(%q): wantErr=%v, got err=%v", tc.input, tc.wantErr, err)
			continue
		}
		if !tc.wantErr && got != tc.want {
			t.Errorf("parseProbeMode(%q): want %v, got %v", tc.input, tc.want, got)
		}
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid kprobe",
			cfg:  Config{Mode: "kprobe", Symbol: "vfs_open"},
		},
		{
			name: "valid kretprobe",
			cfg:  Config{Mode: "kretprobe", Symbol: "vfs_read"},
		},
		{
			name: "valid uprobe with target",
			cfg:  Config{Mode: "uprobe", Symbol: "main", Target: "/usr/bin/myapp"},
		},
		{
			name: "valid uretprobe with target",
			cfg:  Config{Mode: "uretprobe", Symbol: "main", Target: "/usr/bin/myapp"},
		},
		{
			name: "default mode kprobe",
			cfg:  Config{Symbol: "vfs_open"},
		},
		{
			name:    "missing symbol",
			cfg:     Config{Mode: "kprobe"},
			wantErr: true,
		},
		{
			name:    "unknown mode",
			cfg:     Config{Mode: "tracepoint", Symbol: "vfs_open"},
			wantErr: true,
		},
		{
			name:    "uprobe missing target",
			cfg:     Config{Mode: "uprobe", Symbol: "main"},
			wantErr: true,
		},
		{
			name:    "uretprobe missing target",
			cfg:     Config{Mode: "uretprobe", Symbol: "main"},
			wantErr: true,
		},
		{
			name: "kprobe does not require target",
			cfg:  Config{Mode: "kprobe", Symbol: "vfs_open", Target: ""},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Config.Validate(%+v): wantErr=%v, got err=%v", tc.cfg, tc.wantErr, err)
			}
		})
	}
}
