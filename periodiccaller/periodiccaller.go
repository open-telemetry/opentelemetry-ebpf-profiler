// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package periodiccaller allows periodic calls of functions.
package periodiccaller // import "go.opentelemetry.io/ebpf-profiler/periodiccaller"

import (
	"context"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// Start starts a timer that calls <callback> every <interval> until the <ctx> is canceled.
//
// The returned function stops the ticker and blocks until the goroutine has
// exited. Since the goroutine itself only exits once <ctx> is canceled (a
// bare ticker.Stop does not stop the loop), the returned function must only
// be called after <ctx> has already been (or is concurrently being) canceled
// -- otherwise it blocks forever.
func Start(ctx context.Context, interval time.Duration, callback func()) func() {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		defer close(done)
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

	return func() {
		ticker.Stop()
		<-done
	}
}

// CallbackFunc is a function that can be triggered periodically or manually.
// The manualTrigger parameter indicates whether the callback was triggered manually (true)
// or by the periodic timer (false). The return value signals whether the periodic caller
// should continue (true) or stop (false).
type CallbackFunc func(manualTrigger bool) bool

// StartWithManualTrigger starts a timer goroutine that calls <callback> every
// <interval> until the <ctx> is canceled or <callback> returns false.
// The 'trigger' channel can be used to trigger callback immediately.
//
// The returned function stops the ticker and blocks until the goroutine has
// exited. If the goroutine is going to exit only because <ctx> is canceled
// (rather than <callback> returning false), the returned function must only
// be called once that cancellation has already happened -- otherwise it
// blocks forever.
func StartWithManualTrigger(ctx context.Context, interval time.Duration,
	trigger chan bool, callback CallbackFunc) func() {
	ticker := time.NewTicker(interval)
	done := make(chan struct{})
	go func() {
		defer close(done)
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

	return func() {
		ticker.Stop()
		<-done
	}
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
