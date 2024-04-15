/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package reportermetrics implements the fetching and reporting of agent specific metrics.
package reportermetrics

import (
	"context"
	"time"

	"github.com/elastic/otel-profiling-agent/reporter"

	"github.com/elastic/otel-profiling-agent/libpf/periodiccaller"
	"github.com/elastic/otel-profiling-agent/metrics"
)

// report retrieves the reporter metrics and forwards these to the metrics package for processing.
func report(forReporter reporter.Reporter) {
	reporterMetrics := forReporter.GetMetrics()
	metrics.AddSlice([]metrics.Metric{
		{
			ID:    metrics.IDCountsForTracesOverwrite,
			Value: metrics.MetricValue(reporterMetrics.CountsForTracesOverwriteCount),
		},
		{
			ID:    metrics.IDExeMetadataOverwrite,
			Value: metrics.MetricValue(reporterMetrics.ExeMetadataOverwriteCount),
		},
		{
			ID:    metrics.IDFrameMetadataOverwrite,
			Value: metrics.MetricValue(reporterMetrics.FrameMetadataOverwriteCount),
		},
		{
			ID:    metrics.IDFramesForTracesOverwrite,
			Value: metrics.MetricValue(reporterMetrics.FramesForTracesOverwriteCount),
		},
		{
			ID:    metrics.IDHostMetadataOverwrite,
			Value: metrics.MetricValue(reporterMetrics.HostMetadataOverwriteCount),
		},
		{
			ID:    metrics.IDMetricsOverwrite,
			Value: metrics.MetricValue(reporterMetrics.MetricsOverwriteCount),
		},
		{
			ID:    metrics.IDFallbackSymbolsOverwrite,
			Value: metrics.MetricValue(reporterMetrics.FallbackSymbolsOverwriteCount),
		},
		{
			ID:    metrics.IDRPCBytesOutCount,
			Value: metrics.MetricValue(reporterMetrics.RPCBytesOutCount),
		},
		{
			ID:    metrics.IDRPCBytesInCount,
			Value: metrics.MetricValue(reporterMetrics.RPCBytesInCount),
		},
		{
			ID:    metrics.IDWireBytesOutCount,
			Value: metrics.MetricValue(reporterMetrics.WireBytesOutCount),
		},
		{
			ID:    metrics.IDWireBytesInCount,
			Value: metrics.MetricValue(reporterMetrics.WireBytesInCount),
		},
	})
}

// Start starts the reporter specific metric retrieval and reporting.
func Start(mainCtx context.Context, rep reporter.Reporter, interval time.Duration) func() {
	ctx, cancel := context.WithCancel(mainCtx)
	stopReporting := periodiccaller.Start(ctx, interval, func() {
		report(rep)
	})

	return func() {
		cancel()
		stopReporting()
	}
}
