// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golang // import "go.opentelemetry.io/ebpf-profiler/interpreter/go"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}
