/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package metrics

// Create ids.go from metrics.json
//go:generate go run genids/main.go metrics.json ids.go

// MetricID is the type for metric IDs.
type MetricID uint16

// MetricValue is the type for metric values.
type MetricValue int64

// Metric is the type for a metric id/value pair.
type Metric struct {
	ID    MetricID
	Value MetricValue
}

// Summary helps summarizing metrics of the same ID from different sources before
// processing it further.
type Summary map[MetricID]MetricValue

type MetricDefinition struct {
	ID          MetricID   `json:"id"`
	Type        MetricType `json:"type"`
	Description string     `json:"description"`
	Name        string     `json:"name"`
	Field       string     `json:"field"`
	Unit        string     `json:"unit"`
	Obsolete    bool       `json:"obsolete"`
}

type MetricType string

const (
	MetricTypeGauge   MetricType = "gauge"
	MetricTypeCounter MetricType = "counter"
)
