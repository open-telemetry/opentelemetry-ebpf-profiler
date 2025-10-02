// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type option interface {
	apply(*controllerOption) *controllerOption
}

type controllerOption struct {
	executableReporter reporter.ExecutableReporter
	onShutdown         func() error
	configValidation   bool
}

type optFunc func(*controllerOption) *controllerOption

func (f optFunc) apply(c *controllerOption) *controllerOption { return f(c) }

// WithExecutableReporter is a function that allows to configure a ExecutableReporter.
func WithExecutableReporter(executableReporter reporter.ExecutableReporter) option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.executableReporter = executableReporter
		return option
	})
}

// WithOnShutdown is a function that allows to configure a function to be called when the controller is shutdown.
func WithOnShutdown(onShutdown func() error) option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.onShutdown = onShutdown
		return option
	})
}

// WithConfigValidation is a function that enables the validation of the config.
func WithConfigValidation() option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.configValidation = true
		return option
	})
}
