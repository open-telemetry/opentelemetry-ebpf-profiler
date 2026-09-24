// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "thread_context_procs"

type Config struct {
	interpreter.BaseConfig `mapstructure:",squash"`
}

var _ interpreter.Config = Config{}
