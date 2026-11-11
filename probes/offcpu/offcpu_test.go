// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu

import (
	"math"
	"testing"
	"time"

	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
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

func TestTypeMetadata(t *testing.T) {
	tests := map[string]struct {
		threshold  float64
		value      uint64
		wantValue  int64
		wantPeriod int64
	}{
		"capture everything": {threshold: 1.0, value: 1000, wantValue: 1000, wantPeriod: 1},
		"capture 10%":        {threshold: 0.1, value: 1000, wantValue: 10000, wantPeriod: 10},
		"capture 30%":        {threshold: 0.3, value: 3000, wantValue: 10000, wantPeriod: 3},
		// 1e-9 * MaxUint32 truncates to 4, i.e. a period of MaxUint32/4.
		"saturates": {threshold: 1e-9, value: math.MaxUint64, wantValue: math.MaxInt64, wantPeriod: 1 << 30},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			meta := typeMetadata(uint32(tc.threshold * math.MaxUint32))

			if len(meta.SampleTypes) != 1 {
				t.Fatalf("got %d sample types, want 1", len(meta.SampleTypes))
			}
			period := meta.SampleTypes[0].Period
			if period == nil || period.Type != "context_switch" || period.Unit != "count" {
				t.Fatalf("unexpected period: %+v", period)
			}
			if period.Value != tc.wantPeriod {
				t.Errorf("period = %d, want %d", period.Value, tc.wantPeriod)
			}

			got := meta.AppendValues(nil, &samples.TraceEventMeta{ContextValues: []uint64{tc.value}})
			if len(got) != 1 || got[0] != tc.wantValue {
				t.Errorf("values = %v, want [%d]", got, tc.wantValue)
			}

			got = meta.AppendValues(nil, &samples.TraceEventMeta{})
			if len(got) != 1 || got[0] != 0 {
				t.Errorf("values without context = %v, want [0]", got)
			}
		})
	}
}
