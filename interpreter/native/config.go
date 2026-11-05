// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package native // import "go.opentelemetry.io/ebpf-profiler/interpreter/native"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const defaultNameCacheSize = 1024

// Config configures native symbolization from ELF symbol tables.
type Config struct {
	Enabled bool `mapstructure:"enabled" json:"enabled,omitempty"`

	// NameCacheSize is the number of names cached per executable, 1024 if zero.
	NameCacheSize uint32 `mapstructure:"name_cache_size" json:"name_cache_size,omitempty"`

	// MaxSymbols skips executables with more function symbols. Zero is no limit.
	MaxSymbols uint32 `mapstructure:"max_symbols" json:"max_symbols,omitempty"`
}

var _ interpreter.Config = Config{}

func (c Config) IsDisabled() bool { return !c.Enabled }

func (c Config) nameCacheSize() uint32 {
	if c.NameCacheSize == 0 {
		return defaultNameCacheSize
	}
	return c.NameCacheSize
}
