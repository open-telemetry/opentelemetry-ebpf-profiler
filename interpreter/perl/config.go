// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package perl // import "go.opentelemetry.io/ebpf-profiler/interpreter/perl"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "perl_procs"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}
