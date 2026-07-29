// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package periodiccaller allows periodic calls of functions.
package periodiccaller // import "go.opentelemetry.io/ebpf-profiler/periodiccaller"

import (
	"context"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// Start starts a timer that calls <callback> every <interval> until the <ctx> is canceled
// or the returned function is called.
//
// The returned function unconditionally stops the goroutine (it does not
// depend on <ctx> being, or ever becoming, canceled) and blocks until it has
// actually exited -- so it is always safe to call, but must not be called
// from within <callback> itself.
func Start(parentCtx context.Context, interval time.Duration, callback func()) func() {
	ctx, cancel := context.WithCancel(parentCtx)
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
		cancel()
		<-done
	}
}

// CallbackFunc is a function that can be triggered periodically or manually.
// The manualTrigger parameter indicates whether the callback was triggered manually (true)
// or by the periodic timer (false). The return value signals whether the periodic caller
// should continue (true) or stop (false).
type CallbackFunc func(manualTrigger bool) bool

// StartWithManualTrigger starts a timer goroutine that calls <callback> every
// <interval> until the <ctx> is canceled, <callback> returns false, or the
// returned function is called.
// The 'trigger' channel can be used to trigger callback immediately.
//
// The returned function unconditionally stops the goroutine (it does not
// depend on <ctx> being, or ever becoming, canceled, or on <callback> ever
// returning false) and blocks until it has actually exited -- so it is
// always safe to call, but must not be called from within <callback> itself.
func StartWithManualTrigger(parentCtx context.Context, interval time.Duration,
	trigger chan bool, callback CallbackFunc) func() {
	ctx, cancel := context.WithCancel(parentCtx)
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
		cancel()
		<-done
	}
}

// StartWithJitter starts a timer that calls <callback> every <baseDuration+jitter>
// until the <ctx> is canceled or the returned function is called. <jitter>,
// [0..1], is used to add +/- jitter to <baseDuration> at every iteration.
//
// The returned function unconditionally stops the goroutine and blocks until
// it has actually exited -- so it is always safe to call, but must not be
// called from within <callback> itself.
func StartWithJitter(parentCtx context.Context, baseDuration time.Duration, jitter float64,
	callback func()) func() {
	ctx, cancel := context.WithCancel(parentCtx)
	ticker := time.NewTicker(libpf.AddJitter(baseDuration, jitter))
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
			ticker.Reset(libpf.AddJitter(baseDuration, jitter))
		}
	}()

	return func() {
		cancel()
		<-done
	}
}
