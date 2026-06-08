// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "ruby_procs"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}
