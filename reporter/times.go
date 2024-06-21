/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"time"

	"github.com/elastic/otel-profiling-agent/config"
)

// Compile time check to make sure config.Times satisfies the interfaces.
var _ Times = (*config.Times)(nil)

// Times is a subset of config.IntervalsAndTimers.
type Times interface {
	ReportInterval() time.Duration
	ReportMetricsInterval() time.Duration
	GRPCConnectionTimeout() time.Duration
	GRPCOperationTimeout() time.Duration
	GRPCStartupBackoffTime() time.Duration
	GRPCAuthErrorDelay() time.Duration
}
