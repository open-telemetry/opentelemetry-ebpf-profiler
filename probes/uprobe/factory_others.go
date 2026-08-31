// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && (amd64 || arm64))

package uprobe // import "go.opentelemetry.io/ebpf-profiler/probes/uprobe"

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"go.opentelemetry.io/ebpf-profiler/probes/uprobe/internal/metadata"
)

// NewFactory returns an extension.Factory for the uprobe extension.
// The uprobe extension is only functional on Linux amd64/arm64.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		metadata.Type,
		func() component.Config { return &Config{} },
		func(_ context.Context, _ extension.Settings, _ component.Config) (extension.Extension, error) {
			return nil, errors.New("uprobe extension is only supported on Linux amd64/arm64")
		},
		metadata.ExtensionsStability,
	)
}
