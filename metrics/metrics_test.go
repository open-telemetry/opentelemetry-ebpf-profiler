/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package metrics

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReporter struct {
	result chan []Metric
}

func (f fakeReporter) ReportMetrics(_ uint32, ids []uint32, values []int64) {
	metricsResult := make([]Metric, len(ids))

	for j := range ids {
		metricsResult[j].ID = MetricID(ids[j])
		metricsResult[j].Value = MetricValue(values[j])
	}

	// send the result back for comparison with client-side input
	f.result <- metricsResult
}

// TestMetrics
func TestMetrics(t *testing.T) {
	reporter := &fakeReporter{result: make(chan []Metric, 128)}
	SetReporter(reporter)

	// This makes sure that we have enough time to call Add/AddSlice below
	// within the same timestamp (second resolution).
	time.Sleep(1*time.Second - time.Duration(time.Now().Nanosecond()))

	inputMetrics := []Metric{
		{IDCPUUsage, MetricValue(33)},
		{IDIOThroughput, MetricValue(55)},
		{IDIODuration, MetricValue(66)},
		{IDAgentGoRoutines, MetricValue(20)},
	}

	AddSlice(inputMetrics[0:2])                    // 33, 55
	Add(inputMetrics[1].ID, inputMetrics[1].Value) // 55, dropped
	Add(inputMetrics[2].ID, inputMetrics[2].Value) // 66
	AddSlice(inputMetrics[3:4])                    // 20
	Add(inputMetrics[0].ID, inputMetrics[0].Value) // 33, dropped
	AddSlice(inputMetrics[1:3])                    // 55, 66 dropped

	// trigger reporting
	time.Sleep(1 * time.Second)
	AddSlice(nil)

	timeout := time.NewTimer(3 * time.Second)
	select {
	case outputMetrics := <-reporter.result:
		assert.Equal(t, inputMetrics, outputMetrics)
	case <-timeout.C:
		// Timeout
		assert.Fail(t, "timeout - no metrics received in time")
	}
}

func TestGetDefinitions(t *testing.T) {
	defs, err := GetDefinitions()
	require.NoError(t, err)
	assert.Greater(t, len(defs), 1)
}
