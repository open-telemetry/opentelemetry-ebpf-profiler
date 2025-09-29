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
	"go.opentelemetry.io/ebpf-profiler/internal/controller"
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

func BuildProfilesReceiver(options ...option) xreceiver.CreateProfilesFunc {
	return func(ctx context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer xconsumer.Profiles,
	) (xreceiver.Profiles, error) {
		cfg, ok := baseCfg.(*Config)
		if !ok {
			return nil, errInvalidConfig
		}

		controllerOption := &controllerOption{}
		for _, option := range options {
			controllerOption = option.apply(controllerOption)
		}

		controlerCfg := &controller.Config{
			ReporterInterval:       cfg.ReporterInterval,
			MonitorInterval:        cfg.MonitorInterval,
			SamplesPerSecond:       cfg.SamplesPerSecond,
			ProbabilisticInterval:  cfg.ProbabilisticInterval,
			ProbabilisticThreshold: cfg.ProbabilisticThreshold,
			Tracers:                cfg.Tracers,
			ClockSyncInterval:      cfg.ClockSyncInterval,
			SendErrorFrames:        cfg.SendErrorFrames,
			VerboseMode:            cfg.VerboseMode,
			OffCPUThreshold:        cfg.OffCPUThreshold,
			IncludeEnvVars:         cfg.IncludeEnvVars,
			UProbeLinks:            cfg.UProbeLinks,
			LoadProbe:              cfg.LoadProbe,
			MapScaleFactor:         cfg.MapScaleFactor,
			BpfVerifierLogLevel:    cfg.BPFVerifierLogLevel,
			NoKernelVersionCheck:   cfg.NoKernelVersionCheck,
			MaxGRPCRetries:         cfg.MaxGRPCRetries,
			MaxRPCMsgSize:          cfg.MaxRPCMsgSize,
			ExecutableReporter:     controllerOption.executableReporter,
		}

		return internal.NewController(controlerCfg, rs, nextConsumer)
	}
}

func defaultConfig() component.Config {
	return &Config{
		ReporterInterval:       5 * time.Second,
		MonitorInterval:        5 * time.Second,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		Tracers:                "all",
		ClockSyncInterval:      3 * time.Minute,
		MaxGRPCRetries:         5,
		MaxRPCMsgSize:          32 << 20, // 32 MiB,
	}
}
