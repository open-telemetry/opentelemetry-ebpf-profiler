// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package plugins // import "go.opentelemetry.io/ebpf-profiler/plugins"

import "errors"

var (
	// ErrPluginDisabled is returned when Attach is called on a disabled plugin
	ErrPluginDisabled = errors.New("plugin is disabled")
)

// BaseConfig holds the fields required by every plugin config.
// Embed it in each plugin-specific Config to satisfy the Config interface.
type BaseConfig struct {
	Disabled bool `mapstructure:"disabled"`
}

func (b BaseConfig) IsDisabled() bool { return b.Disabled }

// Config is the interface every plugin-specific config must satisfy.
// It is satisfied automatically by embedding BaseConfig.
type Config interface {
	IsDisabled() bool
}

// Per-plugin config types. Each embeds BaseConfig (squashed so mapstructure
// sees Disabled at the same level) and can add plugin-specific fields later.
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

// PluginsConfig holds configuration for all language plugins.
// Zero value means all plugins enabled.
type PluginsConfig struct {
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

// AllPluginsConfig returns a PluginsConfig with all plugins enabled (zero value).
func AllPluginsConfig() PluginsConfig { return PluginsConfig{} }
