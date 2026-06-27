// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package interpreterconfig aggregates per-interpreter configuration.
package interpreterconfig // import "go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"

import (
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/apmint"
	"go.opentelemetry.io/ebpf-profiler/interpreter/beam"
	"go.opentelemetry.io/ebpf-profiler/interpreter/dotnet"
	golang "go.opentelemetry.io/ebpf-profiler/interpreter/go"
	"go.opentelemetry.io/ebpf-profiler/interpreter/golabels"
	"go.opentelemetry.io/ebpf-profiler/interpreter/hotspot"
	"go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"
	"go.opentelemetry.io/ebpf-profiler/interpreter/perl"
	"go.opentelemetry.io/ebpf-profiler/interpreter/php"
	"go.opentelemetry.io/ebpf-profiler/interpreter/python"
	"go.opentelemetry.io/ebpf-profiler/interpreter/ruby"
)

// Config holds configuration for all interpreters.
// By default all interpreters are enabled.
type Config struct {
	Python  python.Config   `mapstructure:"python" json:"python,omitempty"`
	Perl    perl.Config     `mapstructure:"perl" json:"perl,omitempty"`
	PHP     php.Config      `mapstructure:"php" json:"php,omitempty"`
	Hotspot hotspot.Config  `mapstructure:"hotspot" json:"hotspot,omitempty"`
	Ruby    ruby.Config     `mapstructure:"ruby" json:"ruby,omitempty"`
	V8      nodev8.Config   `mapstructure:"v8" json:"v8,omitempty"`
	Dotnet  dotnet.Config   `mapstructure:"dotnet" json:"dotnet,omitempty"`
	Go      golang.Config   `mapstructure:"go" json:"go,omitempty"`
	Labels  golabels.Config `mapstructure:"labels" json:"labels,omitempty"`
	BEAM    beam.Config     `mapstructure:"beam" json:"beam,omitempty"`
}

// AllInterpreters returns a Config with all interpreters enabled.
func AllInterpreters() Config { return Config{} }

// NoInterpreters returns a Config with all interpreters disabled.
func NoInterpreters() Config {
	disabled := interpreter.BaseConfig{Disabled: true}
	return Config{
		Python:  python.Config{BaseConfig: disabled},
		Perl:    perl.Config{BaseConfig: disabled},
		PHP:     php.Config{BaseConfig: disabled},
		Hotspot: hotspot.Config{BaseConfig: disabled},
		Ruby:    ruby.Config{BaseConfig: disabled},
		V8:      nodev8.Config{BaseConfig: disabled},
		Dotnet:  dotnet.Config{BaseConfig: disabled},
		Go:      golang.Config{BaseConfig: disabled},
		Labels:  golabels.Config{BaseConfig: disabled},
		BEAM:    beam.Config{BaseConfig: disabled},
	}
}

// IsMapEnabled returns true if for the given mapName the respective
// configuration is enabled.
func (cfg *Config) IsMapEnabled(mapName string) bool {
	switch mapName {
	case perl.BPFMapName:
		return !cfg.Perl.IsDisabled()
	case php.BPFMapName:
		return !cfg.PHP.IsDisabled()
	case python.BPFMapName:
		return !cfg.Python.IsDisabled()
	case hotspot.BPFMapName:
		return !cfg.Hotspot.IsDisabled()
	case ruby.BPFMapName:
		return !cfg.Ruby.IsDisabled()
	case nodev8.BPFMapName:
		return !cfg.V8.IsDisabled()
	case dotnet.BPFMapName:
		return !cfg.Dotnet.IsDisabled()
	case beam.BPFMapName:
		return !cfg.BEAM.IsDisabled()
	case golabels.BPFMapName, apmint.BPFMapName:
		// go_labels_procs and apm_int_procs are called from
		// unwind_stop and therefore need to be available all the time.
		return true
	default:
		return true // Not an interpreter map, so it should be loaded
	}
}
