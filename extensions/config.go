// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package extensions // import "go.opentelemetry.io/ebpf-profiler/extensions"

import "errors"

var (
	// ErrExtensionDisabled is returned when Attach is called on a disabled extension.
	ErrExtensionDisabled = errors.New("extension is disabled")
)

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

// Per-extension config types. Each embeds BaseConfig (squashed so mapstructure
// sees Disabled at the same level) and can add extension-specific fields later.
type PythonConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type PerlConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type PHPConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type HotspotConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type RubyConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type V8Config struct {
	BaseConfig `mapstructure:",squash"`
}

type DotnetConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type GoConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type LabelsConfig struct {
	BaseConfig `mapstructure:",squash"`
}

type BEAMConfig struct {
	BaseConfig `mapstructure:",squash"`
}

// ExtensionsConfig holds configuration for all extensions.
// By default all extensions are enabled.
type ExtensionsConfig struct {
	Python  PythonConfig  `mapstructure:"python"`
	Perl    PerlConfig    `mapstructure:"perl"`
	PHP     PHPConfig     `mapstructure:"php"`
	Hotspot HotspotConfig `mapstructure:"hotspot"`
	Ruby    RubyConfig    `mapstructure:"ruby"`
	V8      V8Config      `mapstructure:"v8"`
	Dotnet  DotnetConfig  `mapstructure:"dotnet"`
	Go      GoConfig      `mapstructure:"go"`
	Labels  LabelsConfig  `mapstructure:"labels"`
	BEAM    BEAMConfig    `mapstructure:"beam"`
}

// AllExtensionsConfig returns a ExtensionsConfig with all extensions enabled.
func AllExtensionsConfig() ExtensionsConfig { return ExtensionsConfig{} }
