// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu

import (
	"math"
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
		"valid with explicit max_tracked_threads": {
			cfg: Config{Threshold: 1.0, MaxTrackedThreads: 16384},
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
		"max_tracked_threads too large": {
			cfg:     Config{Threshold: 0.5, MaxTrackedThreads: maxTrackedThreadsCap + 1},
			wantErr: true,
		},
		"max_tracked_threads at max": {
			cfg: Config{Threshold: 0.5, MaxTrackedThreads: maxTrackedThreadsCap},
		},
		"max_tracked_threads below auto min": {
			cfg: Config{Threshold: 0.5, MaxTrackedThreads: 1},
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

func TestSchedTimesMaxEntries(t *testing.T) {
	tests := map[string]struct {
		threshold         uint32
		maxTrackedThreads uint32
		want              uint32
	}{
		"explicit size wins": {
			threshold:         math.MaxUint32,
			maxTrackedThreads: 12345,
			want:              12345,
		},
		"explicit size below auto min is kept": {
			threshold:         math.MaxUint32,
			maxTrackedThreads: 1,
			want:              1,
		},
		"auto from full threshold": {
			threshold: math.MaxUint32,
			want:      4096,
		},
		"auto clamps low threshold to min": {
			threshold: 1,
			want:      16,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p := &probe{threshold: tc.threshold, maxTrackedThreads: tc.maxTrackedThreads}
			if got := p.schedTimesMaxEntries(); got != tc.want {
				t.Fatalf("schedTimesMaxEntries() = %d, want %d", got, tc.want)
			}
		})
	}
}
