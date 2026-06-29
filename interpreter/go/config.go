// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "go_procs"

// Config holds the configuration for all Go-specific functionality. Go support
// is split into two independent concerns for Go binaries: symbolization and labels.
// Each concern can be toggled separately
// The go.Disabled value wins over the sub-toggles.
type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`

	// Labels configures eBPF extraction of Go custom goroutine labels.
	// Enabled by default.
	Labels interpreter.BaseConfig `mapstructure:"labels" json:"labels,omitempty"`

	// Symbolization configures userspace symbolization of Go frames via pclntab.
	// Enabled by default.
	Symbolization interpreter.BaseConfig `mapstructure:"symbolization" json:"symbolization,omitempty"`
}

var _ interpreter.Config = Config{}

func (c Config) IsLabelsDisabled() bool {
	return c.Disabled || c.Labels.IsDisabled()
}

func (c Config) IsSymbolizationDisabled() bool {
	return c.Disabled || c.Symbolization.IsDisabled()
}
