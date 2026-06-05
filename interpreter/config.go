// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interpreter // import "go.opentelemetry.io/ebpf-profiler/interpreter"

// BaseConfig holds the fields required by every extension config.
// Embed it in each extension-specific Config to satisfy the Config interface.
type BaseConfig struct {
	Disabled bool `mapstructure:"disabled"`
}

func (b BaseConfig) IsDisabled() bool { return b.Disabled }

// Config is the interface every extension-specific config must satisfy.
// It is satisfied automatically by embedding BaseConfig.
type Config interface {
	IsDisabled() bool
}
