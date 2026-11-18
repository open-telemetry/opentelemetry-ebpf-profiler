// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"
	"go.uber.org/zap/exp/zapslog"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/collector/internal/metadata"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

var errInvalidConfig = errors.New("invalid config")

// NewFactory creates a factory for the receiver.
func NewFactory() receiver.Factory {
	return xreceiver.NewFactory(
		metadata.Type,
		defaultConfig,
		xreceiver.WithProfiles(BuildProfilesReceiver(), metadata.ProfilesStability))
}

func defaultConfig() component.Config {
	return &config.Config{
		ReporterInterval:       5 * time.Second,
		ReporterJitter:         0.2,
		MonitorInterval:        5 * time.Second,
		SamplesPerSecond:       20,
		FrameCacheSize:         uint(pm.DefaultFrameCacheSize),
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		Interpreters:           interpreterconfig.AllInterpreters(),
		ClockSyncInterval:      3 * time.Minute,
		BPFFSRoot:              "/sys/fs/bpf/",
		ErrorMode:              config.PropagateError,
	}
}

func BuildProfilesReceiver(options ...Option) xreceiver.CreateProfilesFunc {
	return func(ctx context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer xconsumer.Profiles,
	) (xreceiver.Profiles, error) {
		log.SetLogger(*slog.New(zapslog.NewHandler(rs.Logger.Core())))

		cfg, ok := baseCfg.(*config.Config)
		if !ok {
			return nil, errInvalidConfig
		}

		opts := &receiverOption{reporterFactory: newCollectorReporter}
		for _, option := range options {
			option.apply(opts)
		}

		return newProfilesReceiver(cfg, opts, rs, nextConsumer)
	}
}

func newCollectorReporter(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error) {
	return reporter.NewCollector(cfg, nextConsumer)
}
