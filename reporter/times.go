// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter

import (
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/times"
)

// Compile time check to make sure config.Times satisfies the interfaces.
var _ Times = (*times.Times)(nil)

// Times is a subset of config.IntervalsAndTimers.
type Times interface {
	ReportInterval() time.Duration
	ReportMetricsInterval() time.Duration
	GRPCConnectionTimeout() time.Duration
	GRPCOperationTimeout() time.Duration
	GRPCStartupBackoffTime() time.Duration
	GRPCAuthErrorDelay() time.Duration
}
