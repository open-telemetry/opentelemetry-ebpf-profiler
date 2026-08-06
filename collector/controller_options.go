// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

type Option interface {
	apply(*controllerOption) *controllerOption
}

type controllerOption struct {
	executableReporter   reporter.ExecutableReporter
	processMetaEnrichers []process.MetaEnricher
	reporterFactory      func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)
	onShutdown           func() error
}

type optFunc func(*controllerOption) *controllerOption

func (f optFunc) apply(c *controllerOption) *controllerOption { return f(c) }

// WithExecutableReporter is a function that allows to configure a ExecutableReporter.
func WithExecutableReporter(executableReporter reporter.ExecutableReporter) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.executableReporter = executableReporter
		return option
	})
}

// WithOnShutdown is a function that allows to configure a function to be called when the controller is shutdown.
func WithOnShutdown(onShutdown func() error) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.onShutdown = onShutdown
		return option
	})
}

// WithReporterFactory is a function that allows to define a custom collector reporter factory.
// If reporterFactory is not set, the default reporter will be used (reporter.NewCollector).
func WithReporterFactory(reporterFactory func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.reporterFactory = reporterFactory
		return option
	})
}

// WithProcessMetaEnricher registers a hook that is called once per process when it
// is first observed and when its executable changes. The enricher may read from /proc or other sources and store
// arbitrary key-value pairs in process.Meta.ExtraMeta. Those values are propagated
// to TraceEventMeta.ExtraMeta, where a SampleAttrProducer can attach them as
// resource or sample attributes on outgoing profiles.
func WithProcessMetaEnricher(enrichers ...process.MetaEnricher) Option {
	return optFunc(func(option *controllerOption) *controllerOption {
		option.processMetaEnrichers = append(option.processMetaEnrichers, enrichers...)
		return option
	})
}
