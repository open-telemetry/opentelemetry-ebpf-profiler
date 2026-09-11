// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigValidate(t *testing.T) {
	for _, tt := range []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{name: "valid default map size", cfg: Config{Threshold: 0.1}},
		{name: "valid map override", cfg: Config{Threshold: 1, MapEntries: 8192}},
		{name: "valid tracepoint mode", cfg: Config{Threshold: 0.1, Mode: ModeTracepoint}},
		{name: "valid tracepoint kprobe mode",
			cfg: Config{Threshold: 0.1, Mode: ModeTracepointKprobe}},
		{name: "zero threshold", cfg: Config{}, wantErr: true},
		{name: "threshold above one", cfg: Config{Threshold: 1.1}, wantErr: true},
		{name: "unknown mode", cfg: Config{Threshold: 0.1, Mode: "unknown"}, wantErr: true},
		{name: "map size above limit", cfg: Config{Threshold: 0.1,
			MapEntries: MaxMapEntries + 1}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestTraceMapSize(t *testing.T) {
	require.Equal(t, uint32(defaultMapEntries), traceMapSize(0))
	require.Equal(t, uint32(8192), traceMapSize(8192))
}
