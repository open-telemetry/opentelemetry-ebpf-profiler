// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package metrics // import "go.opentelemetry.io/ebpf-profiler/metrics"

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"sync"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

var (
	// prevTimestamp holds the timestamp of the buffered metrics
	prevTimestamp libpf.UnixTime32

	// metricsBuffer buffers the metricsBuffer for the timestamp assigned to prevTimestamp
	metricsBuffer = make([]Metric, IDMax)

	// metricIDSet is a bitvector used for fast membership operations, to avoid reporting
	// the same metric ID multiple times in the same batch
	metricIDSet = make([]uint64, 1+(IDMax/64))

	// nMetrics is the number of the current entries in metricsBuffer
	nMetrics int

	// mutex serializes the concurrent calls to AddSlice()
	mutex sync.RWMutex

	//go:embed metrics.json
	metricsJSON []byte

	// Used in fallback checks, e.g. to avoid sending "counters" with 0 values
	metricTypes map[MetricID]MetricType
)

func init() {
	defs, err := GetDefinitions()
	if err != nil {
		panic("extracting definitions from metrics.json")
	}

	metricTypes = make(map[MetricID]MetricType, len(defs))
	for _, md := range defs {
		metricTypes[md.ID] = md.Type
	}
}

// reporterImpl allows swapping out the global metrics reporter.
//
// nil is a valid value indicating that metrics should be voided.
var reporterImpl reporter.MetricsReporter

// SetReporter sets the reporter instance used to send out metrics.
func SetReporter(r reporter.MetricsReporter) {
	reporterImpl = r
}

// report converts and reports collected metrics via the reporter package.
func report() {
	ids := make([]uint32, nMetrics)
	values := make([]int64, nMetrics)

	for i := 0; i < nMetrics; i++ {
		ids[i] = uint32(metricsBuffer[i].ID)
		values[i] = int64(metricsBuffer[i].Value)
	}

	if reporterImpl != nil {
		reporterImpl.ReportMetrics(uint32(prevTimestamp), ids, values)
	}

	nMetrics = 0
	for idx := range metricIDSet {
		metricIDSet[idx] = 0
	}
}

// AddSlice takes a slice of metrics from a metric provider.
// The function buffers the metrics and returns immediately.
//
// Here we collect all metrics until the timestamp changes.
// We then call report() to report all metrics from the previous timestamp.
//
//	|----------------- 1s period -------------|
//	|--+--------------------------+-----------|--+--......
//	|                          |              |
//	report(),AddSlice(ID1)     |              |
//	                           AddSlice(ID2)  |
//	                                          |
//	                                          report(),AddSlice(ID1)
//
// This ensures that the buffered metrics from the previous timestamp are sent
// with the correctly assigned TSMetric.Timestamp.
func AddSlice(newMetrics []Metric) {
	now := libpf.UnixTime32(libpf.NowAsUInt32())

	mutex.Lock()
	defer mutex.Unlock()

	if prevTimestamp != now && nMetrics > 0 {
		report()
	}
	prevTimestamp = now

	if newMetrics == nil {
		return
	}

	for _, metric := range newMetrics {
		if metric.ID <= IDInvalid || metric.ID >= IDMax {
			log.Errorf("Metric value %d out of range [%d,%d]- needs investigation",
				metric.ID, IDInvalid+1, IDMax-1)
			continue
		}

		if metric.Value == 0 && metricTypes[metric.ID] == MetricTypeCounter {
			continue
		}

		idx := metric.ID / 64
		mask := uint64(1) << (metric.ID % 64)
		// Metric IDs 1-7 correspond to CPU/IO/Agent metrics and are scheduled
		// for collection every second. This increases the probability that they will
		// be collected more than once a second, which would trigger this warning.
		// TODO: Remove this when metrics are reworked
		if metricIDSet[idx]&mask > 0 {
			if metric.ID > 7 {
				log.Warnf("Metric ID %d:%v reported multiple times", metric.ID, metric.Value)
			}
			continue
		}

		if nMetrics >= len(metricsBuffer) {
			// Should not happen
			log.Errorf("AddSlice capped reporting to %d metrics - needs investigation",
				len(metricsBuffer))
			continue
		}

		metricIDSet[idx] |= mask
		metricsBuffer[nMetrics].ID = metric.ID
		metricsBuffer[nMetrics].Value = metric.Value
		nMetrics++
	}
}

// Add takes a single metric (id and value) from a metric provider.
// The function buffers the metric and returns immediately.
func Add(id MetricID, value MetricValue) {
	AddSlice([]Metric{{id, value}})
}

// There are two corner cases that we ignore on purpose to simplify the usage.
// We currently don't run into these two cases, likely we never do.
//
// 1. We *only* collect metrics with large intervals. Let's say we collect only once per hour.
//    In this (very special) case, periodiccaller ensures that we report and see the metrics in
//    the storage/UI as soon as a new hour begins. Users who accesses the metrics would likely
//    assume exactly that.
//    Currently, we collect different metrics at 1s intervals.
//
// 2. In case we stop the 'sub package' metrics, we would report the last metrics at least
//    one second later instead of leaving them in the buffer.
//    Currently, we don't stop metric reporting while running host agent.
//    If we do, we possibly don't care for 1s more or less of reported data.
//
// If these assumptions change, we can address that by regularly calling AddSlice() with
// an empty slice. Code can be found in commit 1d01d1ff841891010afaf8d64d4c21a05f19d168
// and earlier.

// GetDefinitions returns the metric definitions from the embedded metrics.json file.
func GetDefinitions() ([]MetricDefinition, error) {
	var definitions []MetricDefinition

	dec := json.NewDecoder(bytes.NewReader(metricsJSON))
	dec.DisallowUnknownFields()

	err := dec.Decode(&definitions)
	if err != nil {
		return nil, err
	}
	return definitions, nil
}
