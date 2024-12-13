// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverprofiles"

	"go.opentelemetry.io/ebpf-profiler/collector/internal"
	"go.opentelemetry.io/ebpf-profiler/internal/controller"
)

var (
	typeStr = component.MustNewType("otelreceiver")

	errInvalidConfig = errors.New("invalid config")
)

// NewFactory creates a factory for the receiver.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		typeStr,
		defaultConfig,
		receiverprofiles.WithProfiles(createProfilesReceiver, component.StabilityLevelAlpha))
}

func createProfilesReceiver(
	_ context.Context,
	_ receiver.Settings, //nolint:gocritic // we must respect the collector API
	baseCfg component.Config,
	nextConsumer consumerprofiles.Profiles) (receiverprofiles.Profiles, error) {
	cfg, ok := baseCfg.(*controller.Config)
	if !ok {
		return nil, errInvalidConfig
	}

	return internal.NewController(cfg, nextConsumer)
}

// todo: export default values (currently in main.go)
func defaultConfig() component.Config {
	return &controller.Config{
		ReporterInterval:       5 * time.Second,
		MonitorInterval:        5 * time.Second,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  1 * time.Minute,
		ProbabilisticThreshold: 100,
		Tracers:                "all",
	}
}
