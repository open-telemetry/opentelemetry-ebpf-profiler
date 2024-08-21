package profilingreceiver

import (
	"context"
	"errors"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/receiver"
	"go.opentelemetry.io/collector/receiver/receiverprofiles"
)

var (
	typeStr = component.MustNewType("otelreceiver")

	errInvalidConfig = errors.New("invalid config")
)

const (
	defaultProjectID = "1"
	defaultHostID    = 0x1234
)

// NewFactory creates a factory for the receiver.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		typeStr,
		createDefaultConfig,
		receiverprofiles.WithProfiles(createProfilesReceiver, component.StabilityLevelAlpha))
}

func createProfilesReceiver(_ context.Context, params receiver.Settings,
	baseCfg component.Config, nextConsumer consumerprofiles.Profiles) (receiverprofiles.Profiles, error) {
	logger := params.Logger
	cfg, ok := baseCfg.(*Config)
	if !ok {
		return nil, errInvalidConfig
	}

	rcvr := &otelReceiver{
		logger:       logger,
		nextConsumer: nextConsumer,
		config:       cfg,
	}

	return rcvr, nil
}
