// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package config // import "go.opentelemetry.io/ebpf-profiler/collector/config"

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap/xconfmap"
)

func TestValidate(t *testing.T) {
	cfg := &Config{
		SamplesPerSecond: 0,
	}
	err := xconfmap.Validate(cfg)
	require.Error(t, err)
	require.Equal(t, "invalid sampling frequency: 0", err.Error())
}
