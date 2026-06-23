// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package php // import "go.opentelemetry.io/ebpf-profiler/interpreter/php"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "php_procs"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}
