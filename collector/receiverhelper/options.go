// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package receiverhelper // import "go.opentelemetry.io/ebpf-profiler/collector/receiverhelper"

import (
	"go.opentelemetry.io/ebpf-profiler/collector/internal"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

// WithExecutableReporter is a function that allows to configure a ExecutableReporter.
func WithExecutableReporter(executableReporter reporter.ExecutableReporter) internal.Option {
	return func(option *internal.ControllerOption) {
		option.ExecutableReporter = executableReporter
	}
}

// WithOnShutdown is a function that allows to define a callback to be called when the controller is shutdown.
func WithOnShutdown(onShutdown func()) internal.Option {
	return func(option *internal.ControllerOption) {
		option.OnShutdown = onShutdown
	}
}
