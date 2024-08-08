/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package periodiccaller allows periodic calls of functions.
package periodiccaller

import (
	"context"
	"time"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
)

// Start starts a timer that calls <callback> every <interval> until the <ctx> is canceled.
func Start(ctx context.Context, interval time.Duration, callback func()) func() {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				callback()
			case <-ctx.Done():
				return
			}
		}
	}()

	return ticker.Stop
}

// StartWithManualTrigger starts a timer that calls <callback> every <interval>
// from <reset> channel until the <ctx> is canceled. Additionally the 'trigger'
// channel can be used to trigger callback immediately.
func StartWithManualTrigger(ctx context.Context, interval time.Duration, trigger chan bool,
	callback func(manualTrigger bool)) func() {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				callback(false)
			case <-trigger:
				callback(true)
			case <-ctx.Done():
				return
			}
		}
	}()

	return ticker.Stop
}

// StartWithJitter starts a timer that calls <callback> every <baseDuration+jitter>
// until the <ctx> is canceled. <jitter>, [0..1], is used to add +/- jitter
// to <baseDuration> at every iteration of the timer.
func StartWithJitter(ctx context.Context, baseDuration time.Duration, jitter float64,
	callback func()) func() {
	ticker := time.NewTicker(libpf.AddJitter(baseDuration, jitter))
	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				callback()
			case <-ctx.Done():
				return
			}
			ticker.Reset(libpf.AddJitter(baseDuration, jitter))
		}
	}()

	return ticker.Stop
}
