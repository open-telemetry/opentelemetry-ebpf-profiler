// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"log/slog"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/xreceiver"
	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/collector/internal"
	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.uber.org/zap/exp/zapslog"
)

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

		controlerCfg := &controller.Config{
			Config:             *cfg,
			ExecutableReporter: controllerOption.executableReporter,
			ReporterFactory:    controllerOption.reporterFactory,
			OnShutdown:         controllerOption.onShutdown,
		}

		return internal.NewController(controlerCfg, rs, nextConsumer)
	}
}
