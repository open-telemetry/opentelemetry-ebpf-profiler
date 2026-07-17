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
	"go.opentelemetry.io/ebpf-profiler/interpreter/hotspot"
	"go.opentelemetry.io/ebpf-profiler/interpreter/luajit"
	"go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"
	"go.opentelemetry.io/ebpf-profiler/interpreter/perl"
	"go.opentelemetry.io/ebpf-profiler/interpreter/php"
	"go.opentelemetry.io/ebpf-profiler/interpreter/python"
	"go.opentelemetry.io/ebpf-profiler/interpreter/ruby"
	"go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"
)

// Config holds configuration for all interpreters.
// By default all interpreters are enabled.
type Config struct {
	Python        python.Config        `mapstructure:"python" json:"python,omitempty"`
	Perl          perl.Config          `mapstructure:"perl" json:"perl,omitempty"`
	PHP           php.Config           `mapstructure:"php" json:"php,omitempty"`
	Hotspot       hotspot.Config       `mapstructure:"hotspot" json:"hotspot,omitempty"`
	Ruby          ruby.Config          `mapstructure:"ruby" json:"ruby,omitempty"`
	V8            nodev8.Config        `mapstructure:"v8" json:"v8,omitempty"`
	Dotnet        dotnet.Config        `mapstructure:"dotnet" json:"dotnet,omitempty"`
	Go            golang.Config        `mapstructure:"go" json:"go,omitempty"`
	BEAM          beam.Config          `mapstructure:"beam" json:"beam,omitempty"`
	LuaJIT        luajit.Config        `mapstructure:"luajit" json:"luajit,omitempty"`
	ThreadContext threadcontext.Config `mapstructure:"thread_context" json:"thread_context,omitempty"`
}

// AllInterpreters returns a Config with all interpreters enabled.
func AllInterpreters() Config { return Config{} }

// NoInterpreters returns a Config with all interpreters disabled.
func NoInterpreters() Config {
	disabled := interpreter.BaseConfig{Disabled: true}
	return Config{
		Python:        python.Config{BaseConfig: disabled},
		Perl:          perl.Config{BaseConfig: disabled},
		PHP:           php.Config{BaseConfig: disabled},
		Hotspot:       hotspot.Config{BaseConfig: disabled},
		Ruby:          ruby.Config{BaseConfig: disabled},
		V8:            nodev8.Config{BaseConfig: disabled},
		Dotnet:        dotnet.Config{BaseConfig: disabled},
		Go:            golang.Config{BaseConfig: disabled},
		BEAM:          beam.Config{BaseConfig: disabled},
		LuaJIT:        luajit.Config{BaseConfig: disabled},
		ThreadContext: threadcontext.Config{BaseConfig: disabled},
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
	case luajit.BPFMapName:
		return !cfg.LuaJIT.IsDisabled()
	case golang.BPFMapName, apmint.BPFMapName, threadcontext.BPFMapName:
		// go_procs is read from collect_trace (preloaded into the PerCPURecord),
		// apm_int_procs and thread_context_procs from unwind_stop, so all three
		// must always be loaded.
		return true
	default:
		return true // Not an interpreter map, so it should be loaded
	}
}
