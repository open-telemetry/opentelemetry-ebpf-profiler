// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package periodiccaller allows periodic calls of functions.
package periodiccaller // import "go.opentelemetry.io/ebpf-profiler/periodiccaller"

import (
	"context"
	"sync"
	"time"
)

// Start starts a timer that calls <callback> every <interval> until the <ctx> is canceled.
func Start(ctx context.Context, interval time.Duration, callback func()) func() {
	return startTickerLoop(ctx, interval, callback, nil)
}

// StartTracked starts a timer that calls <callback> every <interval> until the <ctx> is
// canceled, tracking the goroutine on <wg> for deterministic teardown.
func StartTracked(ctx context.Context, wg *sync.WaitGroup, interval time.Duration,
	callback func(),
) (stop func()) {
	wg.Add(1)
	return startTickerLoop(ctx, interval, callback, wg.Done)
}

// startTickerLoop spawns the timer goroutine shared by Start and StartTracked. The
// optional onExit cleanup runs after any in-flight callback returned.
func startTickerLoop(ctx context.Context, interval time.Duration, callback func(),
	onExit func(),
) (stop func()) {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		if onExit != nil {
			defer onExit()
		}

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

// CallbackFunc is a function that can be triggered periodically or manually.
// The manualTrigger parameter indicates whether the callback was triggered manually (true)
// or by the periodic timer (false). The return value signals whether the periodic caller
// should continue (true) or stop (false).
type CallbackFunc func(manualTrigger bool) bool

// StartWithManualTrigger starts a timer goroutine that calls <callback> every
// <interval> until the <ctx> is canceled or <callback> returns false.
// The 'trigger' channel can be used to trigger callback immediately.
func StartWithManualTrigger(ctx context.Context, interval time.Duration,
	trigger chan bool, callback CallbackFunc) func() {
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if ret := callback(false); !ret {
					return
				}
			case <-trigger:
				if ret := callback(true); !ret {
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return ticker.Stop
}
