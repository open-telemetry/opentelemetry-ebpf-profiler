// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "luajit_procs"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}
