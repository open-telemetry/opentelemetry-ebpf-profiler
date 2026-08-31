// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package offcpu // import "go.opentelemetry.io/ebpf-profiler/probes/offcpu"

import (
	"context"
	"math"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"go.opentelemetry.io/ebpf-profiler/probes/offcpu/internal/metadata"
)

// NewFactory returns an extension.Factory for the offcpu extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		func() component.Config { return &Config{} },
		createExtension,
		metadata.ExtensionStability,
	)
}

func createExtension(_ context.Context, _ extension.Settings, cfg component.Config) (extension.Extension, error) {
	c := cfg.(*Config)
	return &offCPUExtension{p: &probe{
		threshold: uint32(c.Threshold * math.MaxUint32),
	}}, nil
}
