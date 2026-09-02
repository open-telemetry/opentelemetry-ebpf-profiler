// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"
	"go.uber.org/zap/exp/zapslog"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/collector/internal"
	"go.opentelemetry.io/ebpf-profiler/collector/internal/metadata"
	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
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
		MaxGRPCRetries:         5,
		MaxRPCMsgSize:          32 << 20, // 32 MiB
		BPFFSRoot:              "/sys/fs/bpf/",
		ErrorMode:              config.PropagateError,
		ResourceAttributes:     metadata.DefaultResourceAttributesConfig(),
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

		controllerOption := &controllerOption{}
		for _, option := range options {
			controllerOption = option.apply(controllerOption)
		}

		if cfg.ResourceAttributes.ContainerID.Enabled {
			controllerOption.processMetaEnrichers = append(controllerOption.processMetaEnrichers, process.NewContainerIDEnricher())
		}
		if len(cfg.IncludeEnvVars) > 0 {
			envVars := libpf.Set[string]{}
			for envVar := range strings.SplitSeq(cfg.IncludeEnvVars, ",") {
				envVar = strings.TrimSpace(envVar)
				if envVar != "" {
					envVars[envVar] = libpf.Void{}
				}
			}
			controllerOption.processMetaEnrichers = append(controllerOption.processMetaEnrichers, process.NewEnvVarsEnricher(envVars, libpf.Set[string]{}))
		}

		controlerCfg := &controller.Config{
			Config:               *cfg,
			ExecutableReporter:   controllerOption.executableReporter,
			ProcessMetaEnrichers: controllerOption.processMetaEnrichers,
			ReporterFactory:      controllerOption.reporterFactory,
			OnShutdown:           controllerOption.onShutdown,
		}

		return internal.NewController(controlerCfg, rs, nextConsumer)
	}
}
