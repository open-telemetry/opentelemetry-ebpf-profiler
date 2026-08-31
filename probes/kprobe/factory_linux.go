// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package kprobe // import "go.opentelemetry.io/ebpf-profiler/probes/kprobe"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"go.opentelemetry.io/ebpf-profiler/probes/kprobe/internal/metadata"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// NewFactory returns an extension.Factory for the kprobe extension.
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
	mode := c.Mode
	if mode == "" {
		mode = "kprobe"
	}
	// Validate() is called by the framework before createExtension, so
	// parseProbeMode cannot fail here.
	probeMode, err := parseProbeMode(mode)
	if err != nil {
		return nil, err
	}
	return &kprobeExtension{p: &probe{spec: &tracer.ProbeSpec{
		Mode:   probeMode,
		Symbol: c.Symbol,
		Target: c.Target,
	}}}, nil
}
