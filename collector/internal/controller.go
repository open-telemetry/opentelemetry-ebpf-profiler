// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal // import "go.opentelemetry.io/ebpf-profiler/collector/internal"

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/collector/internal/metadata"
	"go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// ProbeProvider is satisfied by any component.Component that also exposes a
// Probe method. It mirrors collector.ProbeExtension without creating a circular
// import between the collector and collector/internal packages.
type ProbeProvider interface {
	Probe() tracer.Probe
}

// Controller is a bridge between the Collector's [receiverprofiles.Profiles]
// interface and our [internal.Controller].
type Controller struct {
	ctlr         *controller.Controller
	onShutdown   func() error
	errorMode    config.ErrorMode
	extensionIDs []component.ID
	probes       []tracer.Probe
}

func NewController(cfg *controller.Config, rs receiver.Settings,
	nextConsumer xconsumer.Profiles,
) (*Controller, error) {
	intervals := times.New(cfg.ReporterInterval,
		cfg.MonitorInterval, cfg.ProbabilisticInterval)

	if cfg.ReporterFactory == nil {
		cfg.ReporterFactory = func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error) {
			return reporter.NewCollector(cfg, nextConsumer)
		}
	}

	// Use the profiler module's own version from the Go module graph.
	// Falls back to the collector's build version (e.g. set by ocb) if the
	// module isn't found, which happens when built outside of a real module context.
	version := rs.BuildInfo.Version
	if buildInfo, ok := debug.ReadBuildInfo(); ok {
		for i := range buildInfo.Deps {
			dep := buildInfo.Deps[i]
			if dep.Path == metadata.ScopeName {
				// dep.Version reflects the required directive and stays set to the original
				// version even when a replace directive redirects the module. Therefore use the
				// replacement's actual version instead.
				if dep.Replace != nil {
					version = dep.Replace.Version
				} else {
					version = dep.Version
				}
			}
		}
	}

	rep, err := cfg.ReporterFactory(&reporter.Config{
		Name:                   metadata.ScopeName,
		Version:                version,
		MaxRPCMsgSize:          cfg.MaxRPCMsgSize,
		MaxGRPCRetries:         cfg.MaxGRPCRetries,
		GRPCOperationTimeout:   intervals.GRPCOperationTimeout(),
		GRPCStartupBackoffTime: intervals.GRPCStartupBackoffTime(),
		GRPCConnectionTimeout:  intervals.GRPCConnectionTimeout(),
		ReportInterval:         intervals.ReportInterval(),
		ReportJitter:           cfg.ReporterJitter,
		SamplesPerSecond:       cfg.SamplesPerSecond,
	}, nextConsumer)
	if err != nil {
		return nil, err
	}
	cfg.Reporter = rep

	// Provide internal metrics via the collectors telemetry.
	meter := rs.MeterProvider.Meter(metadata.ScopeName)
	metrics.Start(meter)

	return &Controller{
		onShutdown:   cfg.OnShutdown,
		ctlr:         controller.New(cfg),
		errorMode:    cfg.ErrorMode,
		extensionIDs: cfg.Probes,
	}, nil
}

// Start the receiver.
func (c *Controller) Start(ctx context.Context, host component.Host) error {
	if err := c.ctlr.Start(ctx); err != nil {
		if c.errorMode == config.IgnoreError {
			c.Shutdown(ctx)
			log.Errorf("eBPF profiler receiver failed, continuing without profiling: %v", err)
			return nil
		}
		return err
	}

	if err := c.enableProbes(ctx, host); err != nil {
		if c.errorMode == config.IgnoreError {
			c.Shutdown(ctx)
			log.Errorf("Failed to enable probe extensions, continuing without them: %v", err)
			return nil
		}
		return err
	}

	return nil
}

// enableProbes resolves each configured extension ID from the host,
// verifies it implements ProbeExtension, and enables its probe on the tracer.
func (c *Controller) enableProbes(ctx context.Context, host component.Host) error {
	if len(c.extensionIDs) == 0 {
		return nil
	}

	extensions := host.GetExtensions()
	for _, id := range c.extensionIDs {
		ext, ok := extensions[id]
		if !ok {
			return fmt.Errorf("extension %q not found; ensure it is listed under service::extensions", id)
		}
		pp, ok := ext.(ProbeProvider)
		if !ok {
			return fmt.Errorf("extension %q does not implement ProbeExtension", id)
		}
		probe := pp.Probe()
		if err := c.ctlr.EnableProbe(ctx, probe); err != nil {
			return fmt.Errorf("enabling probe from extension %q: %w", id, err)
		}
		c.probes = append(c.probes, probe)
		log.Infof("Enabled probe from extension %q", id)
	}
	return nil
}

// Shutdown the receiver.
func (c *Controller) Shutdown(_ context.Context) error {
	var shutdownErr error
	for _, probe := range c.probes {
		if err := probe.Unload(); err != nil {
			shutdownErr = errors.Join(shutdownErr, err)
		}
	}
	c.probes = nil

	c.ctlr.Shutdown()
	if c.onShutdown != nil {
		shutdownErr = errors.Join(shutdownErr, c.onShutdown())
	}
	return shutdownErr
}
