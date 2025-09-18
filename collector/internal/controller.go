// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal // import "go.opentelemetry.io/ebpf-profiler/collector/internal"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"

	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/vc"
)

const (
	ctrlName = "go.opentelemetry.io/ebpf-profiler"
)

// Controller is a bridge between the Collector's [receiverprofiles.Profiles]
// interface and our [internal.Controller]
type Controller struct {
	ctlr       *controller.Controller
	onShutdown func()
}

// Option is a function that allows to configure a ControllerOption.
type Option func(*ControllerOption)

// ControllerOption is the extra configuration for the controller.
type ControllerOption struct {
	ExecutableReporter reporter.ExecutableReporter
	OnShutdown         func()
}

func NewController(cfg *controller.Config, rs receiver.Settings,
	nextConsumer xconsumer.Profiles, opts ...Option) (*Controller, error) {
	controllerOption := ControllerOption{}
	for _, opt := range opts {
		opt(&controllerOption)
	}
	intervals := times.New(cfg.ReporterInterval,
		cfg.MonitorInterval, cfg.ProbabilisticInterval)

	rep, err := reporter.NewCollector(&reporter.Config{
		Name:                   ctrlName,
		Version:                vc.Version(),
		MaxRPCMsgSize:          32 << 20, // 32 MiB
		MaxGRPCRetries:         5,
		GRPCOperationTimeout:   intervals.GRPCOperationTimeout(),
		GRPCStartupBackoffTime: intervals.GRPCStartupBackoffTime(),
		GRPCConnectionTimeout:  intervals.GRPCConnectionTimeout(),
		ReportInterval:         intervals.ReportInterval(),
		SamplesPerSecond:       cfg.SamplesPerSecond,
	}, nextConsumer)
	if err != nil {
		return nil, err
	}
	cfg.Reporter = rep
	cfg.ExecutableReporter = controllerOption.ExecutableReporter

	// Provide internal metrics via the collectors telemetry.
	meter := rs.MeterProvider.Meter(ctrlName)
	metrics.Start(meter)

	return &Controller{
		ctlr:       controller.New(cfg),
		onShutdown: controllerOption.OnShutdown,
	}, nil
}

// Start starts the receiver.
func (c *Controller) Start(ctx context.Context, _ component.Host) error {
	return c.ctlr.Start(ctx)
}

// Shutdown stops the receiver.
func (c *Controller) Shutdown(_ context.Context) error {
	if c.onShutdown != nil {
		c.onShutdown()
	}
	c.ctlr.Shutdown()
	return nil
}
