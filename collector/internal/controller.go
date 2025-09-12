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
	ctlr *controller.Controller
}

func NewController(cfg *controller.Config, rs receiver.Settings,
	nextConsumer xconsumer.Profiles) (*Controller, error) {
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

	// Provide internal metrics via the collectors telemetry.
	meter := rs.MeterProvider.Meter(ctrlName)
	metrics.Start(meter)

	return &Controller{
		ctlr: controller.New(cfg),
	}, nil
}

// Start starts the receiver.
func (c *Controller) Start(ctx context.Context, _ component.Host) error {
	return c.ctlr.Start(ctx)
}

// Shutdown stops the receiver.
func (c *Controller) Shutdown(_ context.Context) error {
	c.ctlr.Shutdown()
	return nil
}
