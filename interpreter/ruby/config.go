// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "ruby_procs"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`

	// SkipNativeResume pushes Ruby cfunc frames inline without transitioning back
	// to the native unwinder. This saves tail calls at the cost of losing native
	// frames within cfuncs.
	SkipNativeResume bool `mapstructure:"skip_native_resume" json:"skip_native_resume,omitempty"`

	// DisableTLS forces execution-context lookup through the main ractor or
	// global pointer, even when ruby_current_ec is available in TLS.
	DisableTLS bool `mapstructure:"disable_tls" json:"disable_tls,omitempty"`

	// DisableECFallback disables the main ractor and global execution-context
	// pointers, requiring ruby_current_ec to be resolved through TLS.
	DisableECFallback bool `mapstructure:"disable_ec_fallback" json:"disable_ec_fallback,omitempty"`
}

var _ interpreter.Config = Config{}
