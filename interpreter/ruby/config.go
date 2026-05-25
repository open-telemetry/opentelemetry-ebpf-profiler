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
	SkipNativeResume bool `mapstructure:"skip_native_resume"`
}

var _ interpreter.Config = Config{}
