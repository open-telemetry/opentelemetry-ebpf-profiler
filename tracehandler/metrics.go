/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package tracehandler

import "github.com/open-telemetry/opentelemetry-ebpf-profiler/metrics"

func (m *traceHandler) collectMetrics() {
	metrics.AddSlice([]metrics.Metric{
		{
			ID:    metrics.IDTraceCacheHit,
			Value: metrics.MetricValue(m.umTraceCacheHit),
		},
		{
			ID:    metrics.IDTraceCacheMiss,
			Value: metrics.MetricValue(m.umTraceCacheMiss),
		},
		{
			ID:    metrics.IDKnownTracesHit,
			Value: metrics.MetricValue(m.bpfTraceCacheHit),
		},
		{
			ID:    metrics.IDKnownTracesMiss,
			Value: metrics.MetricValue(m.bpfTraceCacheMiss),
		},
	})

	m.umTraceCacheHit = 0
	m.umTraceCacheMiss = 0
	m.bpfTraceCacheHit = 0
	m.bpfTraceCacheMiss = 0
}
