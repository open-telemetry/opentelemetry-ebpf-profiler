// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

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
	"go.uber.org/zap/zapcore"
)

// levelOverrideCore wraps a zapcore.Core and overrides its level check,
// allowing entries at or above level to bypass the inner core's AtomicLevel
// filter. Write() is inherited from the embedded Core and does not re-check
// the level per the zapcore.Core contract.
type levelOverrideCore struct {
	zapcore.Core
	level zapcore.Level
}

func (c *levelOverrideCore) Enabled(level zapcore.Level) bool {
	return level >= c.level
}

func (c *levelOverrideCore) Check(entry zapcore.Entry, checked *zapcore.CheckedEntry) *zapcore.CheckedEntry {
	if c.Enabled(entry.Level) {
		return checked.AddCore(entry, c.Core)
	}
	return checked
}

func (c *levelOverrideCore) With(fields []zapcore.Field) zapcore.Core {
	return &levelOverrideCore{Core: c.Core.With(fields), level: c.level}
}

func BuildProfilesReceiver(options ...Option) xreceiver.CreateProfilesFunc {
	return func(_ context.Context,
		rs receiver.Settings,
		baseCfg component.Config,
		nextConsumer xconsumer.Profiles,
	) (xreceiver.Profiles, error) {
		cfg, ok := baseCfg.(*config.Config)
		if !ok {
			return nil, errInvalidConfig
		}

		var core zapcore.Core = rs.Logger.Core()
		if cfg.VerboseMode {
			core = &levelOverrideCore{Core: rs.Logger.Core(), level: zapcore.DebugLevel}
		}
		log.SetLogger(*slog.New(zapslog.NewHandler(core)))

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
