// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package receiverhelper // import "go.opentelemetry.io/ebpf-profiler/collector/receiverhelper"

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
	errInvalidConfig = errors.New("invalid config")
)

func CreateProfilesReceiver(
	_ context.Context,
	rs receiver.Settings,
	baseCfg component.Config,
	nextConsumer xconsumer.Profiles) (xreceiver.Profiles, error) {
	cfg, ok := baseCfg.(*Config)
	if !ok {
		return nil, errInvalidConfig
	}

	controlerCfg := controller.Config{
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
	}
	return internal.NewController(&controlerCfg, rs, nextConsumer)
}

type Config struct {
	ReporterInterval       time.Duration `mapstructure:"reporter_interval"`
	MonitorInterval        time.Duration `mapstructure:"monitor_interval"`
	SamplesPerSecond       int           `mapstructure:"samples_per_second"`
	ProbabilisticInterval  time.Duration `mapstructure:"probabilistic_interval"`
	ProbabilisticThreshold uint          `mapstructure:"probabilistic_threshold"`
	Tracers                string        `mapstructure:"tracers"`
	ClockSyncInterval      time.Duration `mapstructure:"clock_sync_interval"`
	SendErrorFrames        bool          `mapstructure:"send_error_frames"`
	VerboseMode            bool          `mapstructure:"verbose_mode"`
	OffCPUThreshold        float64       `mapstructure:"off_cpu_threshold"`
	IncludeEnvVars         string        `mapstructure:"include_env_vars"`
}
