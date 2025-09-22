// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"

	cController "go.opentelemetry.io/ebpf-profiler/collector/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

var (
	typeStr = component.MustNewType("profiling")

	errInvalidConfig = errors.New("invalid config")
)

// NewFactory creates a factory for the receiver.
func NewFactory() receiver.Factory {
	return xreceiver.NewFactory(
		typeStr,
		defaultConfig,
		xreceiver.WithProfiles(BuildProfilesReceiver(), component.StabilityLevelAlpha))
}

// BuildProfilesReceiver builds a profiles receiver.
func BuildProfilesReceiver(options ...cController.Option) xreceiver.CreateProfilesFunc {
	return func(_ context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer xconsumer.Profiles,
	) (xreceiver.Profiles, error) {
		cfg, ok := baseCfg.(*controller.Config)
		if !ok {
			return nil, errInvalidConfig
		}

		return cController.NewController(cfg, rs, nextConsumer, options...)
	}
}

// WithExecutableReporter allows setting a custom ExecutableReporter in the profiles receiver.
func WithExecutableReporter(executableReporter reporter.ExecutableReporter) cController.Option {
	return cController.OptFunc(func(cfg cController.Config) cController.Config {
		cfg.ExecutableReporter = executableReporter
		return cfg
	})
}

func defaultConfig() component.Config {
	return &controller.Config{
		ReporterInterval:       5 * time.Second,
		MonitorInterval:        5 * time.Second,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		Tracers:                "all",
		ClockSyncInterval:      3 * time.Minute,
	}
}
