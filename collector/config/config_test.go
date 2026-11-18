// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package config // import "go.opentelemetry.io/ebpf-profiler/collector/config"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// validConfig returns a config with valid defaults for testing.
func validConfig() *Config {
	return &Config{
		ReporterInterval:       5 * time.Second,
		MonitorInterval:        5 * time.Second,
		SamplesPerSecond:       20,
		FrameCacheSize:         minFrameCacheSize,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		NoKernelVersionCheck:   true,
		ErrorMode:              PropagateError,
	}
}

func TestValidate(t *testing.T) {
	for _, tt := range []struct {
		name      string
		configure func(*Config)
		wantErr   string
	}{
		{
			name: "zero reporter interval",
			configure: func(cfg *Config) {
				cfg.ReporterInterval = 0
			},
			wantErr: "invalid reporter interval: 0s",
		},
		{
			name: "negative reporter interval",
			configure: func(cfg *Config) {
				cfg.ReporterInterval = -time.Second
			},
			wantErr: "invalid reporter interval: -1s",
		},
		{
			name: "zero monitor interval",
			configure: func(cfg *Config) {
				cfg.MonitorInterval = 0
			},
			wantErr: "invalid monitor interval: 0s",
		},
		{
			name: "negative monitor interval",
			configure: func(cfg *Config) {
				cfg.MonitorInterval = -time.Second
			},
			wantErr: "invalid monitor interval: -1s",
		},
		{
			name: "zero sampling frequency",
			configure: func(cfg *Config) {
				cfg.SamplesPerSecond = 0
			},
			wantErr: "invalid sampling frequency: 0",
		},
		{
			name: "zero frame cache size",
			configure: func(cfg *Config) {
				cfg.FrameCacheSize = 0
			},
			wantErr: "invalid frame cache size 0 (min: 1024, max: 1048576)",
		},
		{
			name: "frame cache size below minimum",
			configure: func(cfg *Config) {
				cfg.FrameCacheSize = minFrameCacheSize - 1
			},
			wantErr: "invalid frame cache size 1023 (min: 1024, max: 1048576)",
		},
		{
			name: "minimum frame cache size",
			configure: func(cfg *Config) {
				cfg.FrameCacheSize = minFrameCacheSize
			},
		},
		{
			name: "maximum frame cache size",
			configure: func(cfg *Config) {
				cfg.FrameCacheSize = maxFrameCacheSize
			},
		},
		{
			name: "frame cache size above maximum",
			configure: func(cfg *Config) {
				cfg.FrameCacheSize = maxFrameCacheSize + 1
			},
			wantErr: "invalid frame cache size 1048577 (min: 1024, max: 1048576)",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.configure(cfg)

			err := confmap.Validate(cfg)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestUnmarshalText(t *testing.T) {
	for _, tt := range []struct {
		name    string
		input   string
		want    ErrorMode
		wantErr bool
	}{
		{
			name:  "ignore",
			input: "ignore",
			want:  IgnoreError,
		},
		{
			name:  "propagate",
			input: "propagate",
			want:  PropagateError,
		},
		{
			name:  "case insensitive",
			input: "IGNORE",
			want:  IgnoreError,
		},
		{
			name:    "invalid value",
			input:   "INVALID",
			wantErr: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var e ErrorMode
			err := e.UnmarshalText([]byte(tt.input))
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, e)
		})
	}
}

func TestPIDNamespaceTranslationModeUnmarshal(t *testing.T) {
	for _, tt := range []struct {
		value   string
		want    tracer.PIDNamespaceTranslationMode
		wantErr bool
	}{
		{value: "none", want: tracer.PIDNamespaceTranslationModeNone},
		{value: "", want: tracer.PIDNamespaceTranslationModeNone},
		{value: "auto", want: tracer.PIDNamespaceTranslationModeAuto},
		{value: "exact", want: tracer.PIDNamespaceTranslationModeExact},
		{value: "recursive", want: tracer.PIDNamespaceTranslationModeRecursive},
		{value: "invalid", wantErr: true},
	} {
		t.Run(tt.value, func(t *testing.T) {
			cfg := validConfig()
			err := confmap.NewFromStringMap(map[string]any{
				"pid_namespace_translation_mode": tt.value,
			}).Unmarshal(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.PIDNamespaceTranslationMode)
		})
	}
}

func TestValidateTargetCPUIDs(t *testing.T) {
	for _, tt := range []struct {
		name         string
		targetCPUIDs string
		wantPinned   []int
		wantErr      bool
	}{
		{
			name:         "empty leaves PinnedCPUIDs unset",
			targetCPUIDs: "",
			wantPinned:   nil,
		},
		{
			name:         "range and single values are parsed into PinnedCPUIDs",
			targetCPUIDs: "0-2,6",
			wantPinned:   []int{0, 1, 2, 6},
		},
		{
			name:         "invalid range is rejected",
			targetCPUIDs: "not-a-range",
			wantErr:      true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.TargetCPUIDs = tt.targetCPUIDs
			err := confmap.Validate(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.wantPinned, cfg.PinnedCPUIDs)
		})
	}
}

func TestValidateErrorMode(t *testing.T) {
	for _, tt := range []struct {
		name      string
		errorMode ErrorMode
		want      ErrorMode
		wantErr   bool
	}{
		{
			name:      "empty error mode is invalid",
			errorMode: "",
			wantErr:   true,
		},
		{
			name:      "ignore is valid",
			errorMode: IgnoreError,
			want:      IgnoreError,
		},
		{
			name:      "propagate is valid",
			errorMode: PropagateError,
			want:      PropagateError,
		},
		{
			name:      "invalid error mode",
			errorMode: "INVALID",
			wantErr:   true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.ErrorMode = tt.errorMode
			err := confmap.Validate(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, cfg.ErrorMode)
		})
	}
}

func TestValidateFilterMinProcessAge(t *testing.T) {
	cfg := validConfig()
	cfg.FilterMinProcessAge = -1 * time.Second

	err := confmap.Validate(cfg)
	require.Error(t, err)
}
