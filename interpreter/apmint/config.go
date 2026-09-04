// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package apmint // import "go.opentelemetry.io/ebpf-profiler/interpreter/apmint"

import "go.opentelemetry.io/ebpf-profiler/interpreter"

const BPFMapName = "apm_int_procs"

// Config holds configuration for the APM integration pseudo-interpreter.
type Config struct {
	interpreter.BaseConfig
}
