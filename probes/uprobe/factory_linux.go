// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package uprobe // import "go.opentelemetry.io/ebpf-profiler/probes/uprobe"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"go.opentelemetry.io/ebpf-profiler/probes/uprobe/internal/metadata"
)

// NewFactory returns an extension.Factory for the uprobe extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		func() component.Config { return &Config{} },
		createExtension,
		metadata.ExtensionStability,
	)
}

func createExtension(_ context.Context, _ extension.Settings, cfg component.Config) (extension.Extension, error) {
	p, err := New(*cfg.(*Config))
	if err != nil {
		return nil, err
	}
	return &uprobeExtension{p: p}, nil
}
