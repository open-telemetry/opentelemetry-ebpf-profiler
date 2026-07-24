// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package config // import "go.opentelemetry.io/ebpf-profiler/collector/config"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap/xconfmap"
)

// validConfig returns a config with valid defaults for testing.
func validConfig() *Config {
	return &Config{
		SamplesPerSecond:       20,
		FrameCacheSize:         minFrameCacheSize,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		NoKernelVersionCheck:   true,
		ErrorMode:              PropagateError,
	}
}

func TestValidate(t *testing.T) {
	cfg := &Config{
		SamplesPerSecond: 0,
		ErrorMode:        PropagateError,
	}
	err := xconfmap.Validate(cfg)
	require.Error(t, err)
	require.Equal(t, "invalid sampling frequency: 0", err.Error())

	// test incompatible config
	invalidCfg := validConfig()
	invalidCfg.PIDNamespaceTranslation = true
	invalidCfg.RootFs = "/host_fs"
	err = xconfmap.Validate(invalidCfg)
	require.Error(t, err)
	require.Equal(t, "pid_namespace_translation and a mounted /proc file system are incompatible arguments due working on different PID namespace levels", err.Error())
}

func TestValidateFrameCacheSize(t *testing.T) {
	for _, tt := range []struct {
		name           string
		frameCacheSize uint
		wantErr        bool
	}{
		{
			name:           "zero is invalid",
			frameCacheSize: 0,
			wantErr:        true,
		},
		{
			name:           "below minimum is invalid",
			frameCacheSize: minFrameCacheSize - 1,
			wantErr:        true,
		},
		{
			name:           "minimum is valid",
			frameCacheSize: minFrameCacheSize,
		},
		{
			name:           "maximum is valid",
			frameCacheSize: maxFrameCacheSize,
		},
		{
			name:           "above maximum is invalid",
			frameCacheSize: maxFrameCacheSize + 1,
			wantErr:        true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.FrameCacheSize = tt.frameCacheSize
			err := xconfmap.Validate(cfg)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
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
			err := xconfmap.Validate(cfg)
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
			err := xconfmap.Validate(cfg)
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

	err := xconfmap.Validate(cfg)
	require.Error(t, err)
}
