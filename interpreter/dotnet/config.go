// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet // import "go.opentelemetry.io/ebpf-profiler/interpreter/dotnet"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "dotnet_procs"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}
