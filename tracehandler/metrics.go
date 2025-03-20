// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracehandler // import "go.opentelemetry.io/ebpf-profiler/tracehandler"

import "go.opentelemetry.io/ebpf-profiler/metrics"

func (m *traceHandler) collectMetrics() {
	metrics.AddSlice([]metrics.Metric{
		{
			ID:    metrics.IDTraceCacheHit,
			Value: metrics.MetricValue(m.traceCacheHit),
		},
		{
			ID:    metrics.IDTraceCacheMiss,
			Value: metrics.MetricValue(m.traceCacheMiss),
		},
	})

	m.traceCacheHit = 0
	m.traceCacheMiss = 0
}
