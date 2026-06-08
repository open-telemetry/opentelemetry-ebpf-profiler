// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "v8_procs"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}
