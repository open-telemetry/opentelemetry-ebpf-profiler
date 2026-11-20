// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/metric/metricdata/metricdatatest"
)

// resetState clears the package-level buffering state so tests don't
// influence each other.
func resetState(t *testing.T) {
	t.Helper()
	origReport := report
	t.Cleanup(func() {
		mutex.Lock()
		defer mutex.Unlock()
		report = origReport
		nMetrics = 0
		prevTimestamp = 0
		for idx := range metricIDSet {
			metricIDSet[idx] = 0
		}
	})
	mutex.Lock()
	defer mutex.Unlock()
	nMetrics = 0
	prevTimestamp = 0
	for idx := range metricIDSet {
		metricIDSet[idx] = 0
	}
}

// TestMetrics
func TestMetrics(t *testing.T) {
	resetState(t)
	// NOP report to avoid timing-based interference.
	report = func() {}

	inputMetrics := []Metric{
		{IDELFInfoCacheHit, MetricValue(33)},
		{IDELFInfoCacheMiss, MetricValue(55)},
		{IDErrProcESRCH, MetricValue(66)},
		{IDErrProcNotExist, MetricValue(20)},
		{IDUnwindCallInterpreter, MetricValue(0)},
	}

	meter := noop.NewMeterProvider().Meter("test")
	Start(meter)

	AddSlice(inputMetrics[0:2])                    // 33, 55
	Add(inputMetrics[1].ID, inputMetrics[1].Value) // 55, dropped
	Add(inputMetrics[2].ID, inputMetrics[2].Value) // 66
	AddSlice(inputMetrics[3:4])                    // 20
	Add(inputMetrics[0].ID, inputMetrics[0].Value) // 33, dropped
	AddSlice(inputMetrics[1:3])                    // 55, 66 dropped
	AddSlice(inputMetrics[2:5])                    // 66 dropped, 20 dropped, 0 dropped
	// Drop counter with 0 value as we don't expect it to appear in output
	inputMetrics = inputMetrics[:4]

	outputMetrics := make([]Metric, nMetrics)
	for j := range nMetrics {
		outputMetrics[j].ID = metricsBuffer[j].ID
		outputMetrics[j].Value = metricsBuffer[j].Value
	}
	assert.Equal(t, inputMetrics, outputMetrics)
}

func TestGetDefinitions(t *testing.T) {
	defs := GetDefinitions()
	assert.Greater(t, len(defs), 1)
}

// TestOTelMetrics verifies that buffered metrics are reported via the
// OTel metrics API with the expected names, descriptions, units, types and values.
func TestOTelMetrics(t *testing.T) {
	resetState(t)

	reader := sdkmetric.NewManualReader()
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() {
		_ = provider.Shutdown(context.WithoutCancel(t.Context()))
	})

	const scopeName = "go.opentelemetry.io/ebpf-profiler/metrics/test"
	Start(provider.Meter(scopeName))
	t.Cleanup(func() { Start(noop.Meter{}) })
	require.True(t, Enabled())

	defs := make(map[MetricID]MetricDefinition)
	for _, d := range GetDefinitions() {
		defs[d.ID] = d
	}

	// flush reports all currently buffered metrics, independent of timing.
	flush := func() {
		mutex.Lock()
		defer mutex.Unlock()
		report()
	}

	AddSlice([]Metric{
		{IDELFInfoCacheHit, 33},
		{IDELFInfoCacheMiss, 55},
		{IDUnwindCallInterpreter, 0}, // zero-valued counter, dropped
		{IDUnwindInfoArraySize, 7},
	})
	flush()

	// Counters accumulate, gauges report the last recorded value.
	AddSlice([]Metric{
		{IDELFInfoCacheHit, 10},
		{IDUnwindInfoArraySize, 3},
	})
	flush()

	counter := func(id MetricID, value int64) metricdata.Metrics {
		d := defs[id]
		require.Equal(t, MetricTypeCounter, d.Type)
		return metricdata.Metrics{
			Name:        d.Field,
			Description: d.Description,
			Unit:        d.Unit,
			Data: metricdata.Sum[int64]{
				Temporality: metricdata.CumulativeTemporality,
				IsMonotonic: true,
				DataPoints:  []metricdata.DataPoint[int64]{{Value: value}},
			},
		}
	}
	gauge := func(id MetricID, value int64) metricdata.Metrics {
		d := defs[id]
		require.Equal(t, MetricTypeGauge, d.Type)
		return metricdata.Metrics{
			Name:        d.Field,
			Description: d.Description,
			Unit:        d.Unit,
			Data: metricdata.Gauge[int64]{
				DataPoints: []metricdata.DataPoint[int64]{{Value: value}},
			},
		}
	}

	var rm metricdata.ResourceMetrics
	require.NoError(t, reader.Collect(t.Context(), &rm))
	require.Len(t, rm.ScopeMetrics, 1)

	want := metricdata.ScopeMetrics{
		Scope: instrumentation.Scope{Name: scopeName},
		Metrics: []metricdata.Metrics{
			counter(IDELFInfoCacheHit, 43),
			counter(IDELFInfoCacheMiss, 55),
			gauge(IDUnwindInfoArraySize, 3),
		},
	}
	metricdatatest.AssertEqual(t, want, rm.ScopeMetrics[0],
		metricdatatest.IgnoreTimestamp())
}
