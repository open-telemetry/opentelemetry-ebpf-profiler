// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package controller // import "go.opentelemetry.io/ebpf-profiler/collector/internal/controller"

import "go.opentelemetry.io/ebpf-profiler/reporter"

type Config struct {
	ExecutableReporter reporter.ExecutableReporter
}

// Option configures a [Controller].
type Option interface {
	apply(Config) Config
}

type OptFunc func(Config) Config

func (f OptFunc) apply(c Config) Config { return f(c) }
