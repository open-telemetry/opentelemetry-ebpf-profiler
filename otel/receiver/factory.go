package profilingreceiver

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

var (
	typeStr = component.MustNewType("otelreceiver")
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
		receiver.WithTraces(createTracesReceiver, component.StabilityLevelAlpha))
}

//nolint:gocritic
func createTracesReceiver(_ context.Context, params receiver.Settings,
	baseCfg component.Config, nextConsumer consumer.Traces) (receiver.Traces, error) {
	logger := params.Logger
	tracerCfg := baseCfg.(*Config)

	traceRcvr := &otelReceiver{
		logger:       logger,
		nextConsumer: nextConsumer,
		config:       tracerCfg,
	}

	return traceRcvr, nil
}
