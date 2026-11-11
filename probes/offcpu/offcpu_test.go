// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu

import (
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	tests := map[string]struct {
		cfg     Config
		wantErr bool
	}{
		"valid threshold only": {
			cfg: Config{Threshold: 0.1},
		},
		"valid with min_duration": {
			cfg: Config{Threshold: 1.0, MinDuration: time.Second},
		},
		"min_duration zero disables filter": {
			cfg: Config{Threshold: 0.5, MinDuration: 0},
		},
		"threshold zero": {
			cfg:     Config{Threshold: 0},
			wantErr: true,
		},
		"threshold negative": {
			cfg:     Config{Threshold: -0.1},
			wantErr: true,
		},
		"threshold above one": {
			cfg:     Config{Threshold: 1.1},
			wantErr: true,
		},
		"min_duration negative": {
			cfg:     Config{Threshold: 0.5, MinDuration: -time.Millisecond},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}
