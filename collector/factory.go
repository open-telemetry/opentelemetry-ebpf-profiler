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

	"go.opentelemetry.io/ebpf-profiler/collector/internal"
	"go.opentelemetry.io/ebpf-profiler/controller"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/vc"
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
		xreceiver.WithProfiles(createProfilesReceiver, component.StabilityLevelAlpha))
}

func createProfilesReceiver(
	_ context.Context,
	_ receiver.Settings, //nolint:gocritic // we must respect the collector API
	baseCfg component.Config,
	nextConsumer xconsumer.Profiles) (xreceiver.Profiles, error) {
	cfg, ok := baseCfg.(*controller.Config)
	if !ok {
		return nil, errInvalidConfig
	}

	return internal.NewController(cfg, nextConsumer)
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
		ReporterConfigFactory: func(intervals *times.Times, samplesPerSecond int) *reporter.Config {
			return &reporter.Config{
				Name:                   "otelcol-ebpf-profiler",
				Version:                vc.Version(),
				MaxRPCMsgSize:          32 << 20, // 32 MiB
				MaxGRPCRetries:         5,
				GRPCOperationTimeout:   intervals.GRPCOperationTimeout(),
				GRPCStartupBackoffTime: intervals.GRPCStartupBackoffTime(),
				GRPCConnectionTimeout:  intervals.GRPCConnectionTimeout(),
				ReportInterval:         intervals.ReportInterval(),
				SamplesPerSecond:       samplesPerSecond,
			}
		},
	}
}
