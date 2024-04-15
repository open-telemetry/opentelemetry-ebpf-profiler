/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

import (
	"time"

	log "github.com/sirupsen/logrus"
)

var times = Times{
	reportMetricsInterval: 1 * time.Minute,
	// GRPCAuthErrorDelay defines the delay before triggering a global process exit after a
	// gRPC auth error.
	grpcAuthErrorDelay: 10 * time.Minute,
	// GRPCConnectionTimeout defines the timeout for each established gRPC connection.
	grpcConnectionTimeout: 3 * time.Second,
	// GRPCOperationTimeout defines the timeout for each gRPC operation.
	grpcOperationTimeout: 5 * time.Second,
	// GRPCStartupBackoffTimeout defines the time between failed gRPC requests during startup
	// phase.
	grpcStartupBackoffTimeout: 1 * time.Minute,
	pidCleanupInterval:        5 * time.Minute,
	tracePollInterval:         250 * time.Millisecond,
}

// Compile time check for interface adherence
var _ IntervalsAndTimers = (*Times)(nil)

// Times hold all the intervals and timeouts that are used across the host agent in a central place
// and comes with Getters to read them.
type Times struct {
	monitorInterval           time.Duration
	tracePollInterval         time.Duration
	reportInterval            time.Duration
	reportMetricsInterval     time.Duration
	grpcConnectionTimeout     time.Duration
	grpcOperationTimeout      time.Duration
	grpcStartupBackoffTimeout time.Duration
	grpcAuthErrorDelay        time.Duration
	pidCleanupInterval        time.Duration
	probabilisticInterval     time.Duration
}

// IntervalsAndTimers is a meta interface that exists purely to document its functionality.
type IntervalsAndTimers interface {
	// MonitorInterval defines the interval for PID event monitoring and metric collection.
	MonitorInterval() time.Duration
	// TracePollInterval defines the interval at which we read the trace perf event buffer.
	TracePollInterval() time.Duration
	// ReportInterval defines the interval at which collected data is sent to collection agent.
	ReportInterval() time.Duration
	// ReportMetricsInterval defines the interval at which collected metrics are sent
	// to collection agent.
	ReportMetricsInterval() time.Duration
	// GRPCConnectionTimeout defines the timeout for each established gRPC connection.
	GRPCConnectionTimeout() time.Duration
	// GRPCOperationTimeout defines the timeout for each gRPC operation.
	GRPCOperationTimeout() time.Duration
	// GRPCStartupBackoffTime defines the time between failed gRPC requests during startup
	// phase.
	GRPCStartupBackoffTime() time.Duration
	// GRPCAuthErrorDelay defines the delay before triggering a global process exit after a
	// gRPC auth error.
	GRPCAuthErrorDelay() time.Duration
	// PIDCleanupInterval defines the interval at which monitored PIDs are checked for
	// liveness and no longer alive PIDs are cleaned up.
	PIDCleanupInterval() time.Duration
	// ProbabilisticInterval defines the interval for which probabilistic profiling will
	// be enabled or disabled.
	ProbabilisticInterval() time.Duration
}

func (t *Times) MonitorInterval() time.Duration { return t.monitorInterval }

func (t *Times) TracePollInterval() time.Duration { return t.tracePollInterval }

func (t *Times) ReportInterval() time.Duration { return t.reportInterval }

func (t *Times) ReportMetricsInterval() time.Duration { return t.reportMetricsInterval }

func (t *Times) GRPCConnectionTimeout() time.Duration { return t.grpcConnectionTimeout }

func (t *Times) GRPCOperationTimeout() time.Duration { return t.grpcOperationTimeout }

func (t *Times) GRPCStartupBackoffTime() time.Duration { return t.grpcStartupBackoffTimeout }

func (t *Times) GRPCAuthErrorDelay() time.Duration { return t.grpcAuthErrorDelay }

func (t *Times) PIDCleanupInterval() time.Duration { return t.pidCleanupInterval }

func (t *Times) ProbabilisticInterval() time.Duration { return t.probabilisticInterval }

// GetTimes provides access to all timers and intervals.
func GetTimes() *Times {
	if !configurationSet {
		log.Fatal("Cannot get Times. Configuration has not been read")
	}
	return &times
}
