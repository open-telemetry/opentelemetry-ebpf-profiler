// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package native // import "go.opentelemetry.io/ebpf-profiler/interpreter/native"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const defaultNameCacheSize = interpreter.LruFunctionCacheSize

// Config configures native symbolization from ELF symbol tables.
type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`

	// NameCacheSize is the number of names cached per executable, 1024 if zero.
	NameCacheSize uint32 `mapstructure:"name_cache_size" json:"name_cache_size,omitempty"`
}

var _ interpreter.Config = Config{}

func (c Config) nameCacheSize() uint32 {
	if c.NameCacheSize == 0 {
		return defaultNameCacheSize
	}
	return c.NameCacheSize
}
