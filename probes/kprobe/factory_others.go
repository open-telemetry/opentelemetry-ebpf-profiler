// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !(linux && (amd64 || arm64))

package kprobe // import "go.opentelemetry.io/ebpf-profiler/probes/kprobe"

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
)

// NewFactory returns an extension.Factory for the kprobe extension.
// The kprobe extension is only functional on Linux amd64/arm64.
func NewFactory() extension.Factory {
	return extension.NewFactory(
		Type,
		func() component.Config { return &Config{} },
		func(_ context.Context, _ extension.Settings, _ component.Config) (extension.Extension, error) {
			return nil, errors.New("kprobe extension is only supported on Linux amd64/arm64")
		},
		stability,
	)
}
