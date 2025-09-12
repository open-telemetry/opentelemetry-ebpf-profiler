// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package internal // import "go.opentelemetry.io/ebpf-profiler/collector/internal"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"

	"go.opentelemetry.io/ebpf-profiler/controller"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
)

// Controller is a bridge between the Collector's [receiverprofiles.Profiles]
// interface and our [internal.Controller]
type Controller struct {
	ctlr *controller.Controller
}

func NewController(cfg *controller.Config,
	nextConsumer xconsumer.Profiles) (*Controller, error) {
	intervals := times.New(cfg.ReporterInterval,
		cfg.MonitorInterval, cfg.ProbabilisticInterval)
	reporterConfig := cfg.ReporterConfigFactory(intervals, cfg.SamplesPerSecond)
	rep, err := reporter.NewCollector(reporterConfig, nextConsumer)
	if err != nil {
		return nil, err
	}
	cfg.Reporter = rep

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
