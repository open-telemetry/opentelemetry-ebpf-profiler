// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverprofiles"

	"go.opentelemetry.io/ebpf-profiler/collector/internal"
)

var (
	typeStr = component.MustNewType("otelreceiver")

	errInvalidConfig = errors.New("invalid config")
)

// NewFactory creates a factory for the receiver.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		typeStr,
		internal.CreateDefaultConfig,
		receiverprofiles.WithProfiles(createProfilesReceiver, component.StabilityLevelAlpha))
}

func createProfilesReceiver(
	_ context.Context,
	params receiver.Settings, //nolint:gocritic // we must respect the collector API
	baseCfg component.Config,
	nextConsumer consumerprofiles.Profiles) (receiverprofiles.Profiles, error) {
	logger := params.Logger
	cfg, ok := baseCfg.(*internal.Config)
	if !ok {
		return nil, errInvalidConfig
	}

	rcvr := internal.NewController(logger, nextConsumer, cfg)
	return rcvr, nil
}
