// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package uprobe

import "testing"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid",
			cfg:  Config{Target: "/usr/lib/libc.so.6", Symbol: "malloc"},
		},
		{
			name:    "missing target",
			cfg:     Config{Symbol: "malloc"},
			wantErr: true,
		},
		{
			name:    "missing symbol",
			cfg:     Config{Target: "/usr/lib/libc.so.6"},
			wantErr: true,
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

func TestNewFactory(t *testing.T) {
	if factory := NewFactory(); factory == nil {
		t.Fatal("NewFactory returned nil")
	}
}
