// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracehandler // import "go.opentelemetry.io/ebpf-profiler/tracehandler"

import "go.opentelemetry.io/ebpf-profiler/metrics"

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
