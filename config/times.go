/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

import (
	"context"
	"math"
	"runtime"
	"sort"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/elastic/otel-profiling-agent/periodiccaller"
	"github.com/elastic/otel-profiling-agent/util"
)

const (
	// Number of timing samples to use when retrieving system boot time.
	sampleSize = 5
	// In the kernel, we retrieve timestamps from a monotonic clock
	// (bpf_ktime_get_ns) that does not count system suspend time.
	// In userspace, we try to detect system suspend events by diffing
	// with values retrieved from a monotonic clock that does count
	// system suspend time. If the delta exceeds the following threshold
	// (10s), we add it to the monotonic 'delta' that we keep track of.
	monotonicThresholdNs = 10 * 1e9

	// GRPCAuthErrorDelay defines the delay before triggering a global process exit after a
	// gRPC auth error.
	GRPCAuthErrorDelay = 10 * time.Minute
	// GRPCConnectionTimeout defines the timeout for each established gRPC connection.
	GRPCConnectionTimeout = 3 * time.Second
	// GRPCOperationTimeout defines the timeout for each gRPC operation.
	GRPCOperationTimeout = 5 * time.Second
	// GRPCStartupBackoffTimeout defines the time between failed gRPC requests during startup
	// phase.
	GRPCStartupBackoffTimeout = 1 * time.Minute
)

var (
	monotonicDeltaNs      atomic.Int64
	monotonicSyncInterval = 1 * time.Minute
)

var times = Times{
	reportMetricsInterval:     1 * time.Minute,
	grpcAuthErrorDelay:        GRPCAuthErrorDelay,
	grpcConnectionTimeout:     GRPCConnectionTimeout,
	grpcOperationTimeout:      GRPCOperationTimeout,
	grpcStartupBackoffTimeout: GRPCStartupBackoffTimeout,
	pidCleanupInterval:        5 * time.Minute,
	tracePollInterval:         250 * time.Millisecond,
	bootTimeUnixNano:          getBootTimeUnixNano(),
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
	bootTimeUnixNano          int64
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
	// BootTimeUnixNano defines the system boot time in nanoseconds since the epoch. This value
	// can be used to convert monotonic time (e.g. util.GetKTime) to Unix time, by adding it
	// as a delta.
	BootTimeUnixNano() int64
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

func (t *Times) BootTimeUnixNano() int64 {
	return t.bootTimeUnixNano + monotonicDeltaNs.Load()
}

// GetTimes provides access to all timers and intervals.
func GetTimes() *Times {
	if !configurationSet {
		log.Fatal("Cannot get Times. Configuration has not been read")
	}
	return &times
}

// StartMonotonicSync starts a goroutine that periodically calculates a delta
// between the two monotonic clocks (CLOCK_MONOTONIC and CLOCK_BOOTTIME). This
// delta can be introduced by system suspend events. For more information, see
// clock_gettime(2).
func StartMonotonicSync(ctx context.Context) {
	initialDelta := getDelta(0)
	log.Debugf("Initial monotonic clock delta: %v", initialDelta)

	periodiccaller.Start(ctx, monotonicSyncInterval, func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		minDelta := int64(math.MaxInt64)
		for i := 0; i < sampleSize; i++ {
			d := getDelta(initialDelta)
			if d < 0 {
				d = -d
			}
			// We're interested in the minimum absolute delta between the two clocks
			if d < minDelta {
				minDelta = d
			}
		}

		if minDelta >= monotonicThresholdNs {
			monotonicDeltaNs.Add(minDelta)
		}
	})
}

func getDelta(compensationValue int64) int64 {
	var ts unix.Timespec

	// Does not include suspend time
	kt := int64(util.GetKTime())
	// Does include suspend time
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		// This should never happen in our target environments.
		return 0
	}

	delta := (kt + monotonicDeltaNs.Load()) - ts.Nano() - compensationValue

	return delta
}

// getBootTimeUnixNano returns system boot time in nanoseconds since the
// epoch, temporarily locking the calling goroutine to its OS thread.
func getBootTimeUnixNano() int64 {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	samples := make([]struct {
		t1    time.Time
		ktime int64
		t2    time.Time
	}, sampleSize)

	for i := range samples {
		// To avoid noise from scheduling / other delays, we perform a
		// series of measurements and pick the one with lowest delta.
		samples[i].t1 = time.Now()
		samples[i].ktime = int64(util.GetKTime())
		samples[i].t2 = time.Now()
	}

	sort.Slice(samples, func(i, j int) bool {
		di := samples[i].t2.UnixNano() - samples[i].t1.UnixNano()
		dj := samples[j].t2.UnixNano() - samples[j].t1.UnixNano()
		if di < 0 {
			di = -di
		}
		if dj < 0 {
			dj = -dj
		}
		return di < dj
	})

	// This should never be negative, as t1.UnixNano() >> ktime
	return samples[0].t1.UnixNano() - samples[0].ktime
}
