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
	apply(*receiverOption)
}

type receiverOption struct {
	executableReporter   reporter.ExecutableReporter
	processMetaEnrichers []process.MetaEnricher
	reporterFactory      func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)
	onShutdown           func() error
}

type optFunc func(*receiverOption)

func (f optFunc) apply(c *receiverOption) { f(c) }

// WithExecutableReporter is a function that allows to configure a ExecutableReporter.
func WithExecutableReporter(executableReporter reporter.ExecutableReporter) Option {
	return optFunc(func(option *receiverOption) {
		option.executableReporter = executableReporter
	})
}

// WithOnShutdown is a function that allows to configure a function to be called when the controller is shutdown.
func WithOnShutdown(onShutdown func() error) Option {
	return optFunc(func(option *receiverOption) {
		option.onShutdown = onShutdown
	})
}

// WithReporterFactory is a function that allows to define a custom collector reporter factory.
// Without it the default reporter (reporter.NewCollector) is used.
func WithReporterFactory(reporterFactory func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error)) Option {
	return optFunc(func(option *receiverOption) {
		option.reporterFactory = reporterFactory
	})
}

// WithProcessMetaEnricher registers a hook that is called once per process when it
// is first observed and when its executable changes. The enricher may read from /proc or other sources and store
// arbitrary key-value pairs in process.Meta.ExtraMeta. Those values are propagated
// to TraceEventMeta.ExtraMeta, where a SampleAttrProducer can attach them as
// resource or sample attributes on outgoing profiles.
func WithProcessMetaEnricher(enrichers ...process.MetaEnricher) Option {
	return optFunc(func(option *receiverOption) {
		option.processMetaEnrichers = append(option.processMetaEnrichers, enrichers...)
	})
}
