// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"go.opentelemetry.io/ebpf-profiler/probes/heap/internal/metadata"
)

// NewFactory returns an extension.Factory for the heap profiling extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		func() component.Config { return &Config{} },
		createExtension,
		metadata.ExtensionsStability,
	)
}

func createExtension(_ context.Context, _ extension.Settings, cfg component.Config) (extension.Extension, error) {
	return &heapExtension{p: New(*cfg.(*Config))}, nil
}
