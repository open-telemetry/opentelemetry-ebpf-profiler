/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package agentmetrics implements the fetching and reporting of agent specific metrics.
package agentmetrics

import (
	"context"
	"runtime"
	"time"

	"github.com/elastic/otel-profiling-agent/metrics"
	"github.com/elastic/otel-profiling-agent/periodiccaller"
	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
)

// rusageTimes holdes time values of a rusage call.
type rusageTimes struct {
	// utime represents the user time in usec.
	utime unix.Timeval
	// stime represents the system time in usec.
	stime unix.Timeval
}

const (
	// rusageSelf is the indicator that we get the rusage
	// of the calling process itself.
	rusageSelf = 0
)

// timeDelta calculates the difference between two time values
// and returns the difference in milliseconds.
func timeDelta(now, prev unix.Timeval) int64 {
	secDelta := (now.Sec - prev.Sec) * 1000
	usecDelta := (now.Usec - prev.Usec) / 1000
	return secDelta + usecDelta
}

// report collects agent specific metrics and forwards these
// to the metrics package for further processing.
func (r *rusageTimes) report() {
	nGoRoutines := runtime.NumGoroutine()

	var stats runtime.MemStats
	runtime.ReadMemStats(&stats)

	var rusage unix.Rusage
	if err := unix.Getrusage(rusageSelf, &rusage); err != nil {
		log.Errorf("Failed to fetch Rusage: %v", err)
		return
	}

	// Get the difference to the previous call of rusage.
	deltaStime := timeDelta(rusage.Stime, r.stime)
	deltaUtime := timeDelta(rusage.Utime, r.utime)

	// Save the current values of the rusage call.
	r.stime = rusage.Stime
	r.utime = rusage.Utime

	metrics.AddSlice([]metrics.Metric{
		{
			ID:    metrics.IDAgentGoRoutines,
			Value: metrics.MetricValue(nGoRoutines),
		},
		{
			ID:    metrics.IDAgentHeapAlloc,
			Value: metrics.MetricValue(stats.HeapAlloc),
		},
		{
			ID:    metrics.IDAgentUTime,
			Value: metrics.MetricValue(deltaUtime),
		},
		{
			ID:    metrics.IDAgentSTime,
			Value: metrics.MetricValue(deltaStime),
		},
	})
}

// Start starts the agent specific metric retrieval and reporting.
func Start(mainCtx context.Context, interval time.Duration) (func(), error) {
	var rusage unix.Rusage
	if err := unix.Getrusage(rusageSelf, &rusage); err != nil {
		log.Errorf("Failed to fetch Rusage: %v", err)
		return func() {}, err
	}

	prev := rusageTimes{
		utime: rusage.Utime,
		stime: rusage.Stime,
	}

	ctx, cancel := context.WithCancel(mainCtx)
	stopReporting := periodiccaller.Start(ctx, interval, func() {
		prev.report()
	})

	return func() {
		cancel()
		stopReporting()
	}, nil
}
