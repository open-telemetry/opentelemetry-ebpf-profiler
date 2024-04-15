/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package periodiccaller allows periodic calls of functions.
package periodiccaller

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/goleak"
)

// TestPeriodicCaller tests periodic calling for all exported periodiccaller functions
func TestPeriodicCaller(t *testing.T) {
	// goroutine leak detector, see https://github.com/uber-go/goleak
	defer goleak.VerifyNone(t)
	interval := 10 * time.Millisecond
	trigger := make(chan bool)

	tests := map[string]func(context.Context, func()) func(){
		"Start": func(ctx context.Context, cb func()) func() {
			return Start(ctx, interval, cb)
		},
		"StartWithJitter": func(ctx context.Context, cb func()) func() {
			return StartWithJitter(ctx, interval, 0.2, cb)
		},
		"StartWithManualTrigger": func(ctx context.Context, cb func()) func() {
			return StartWithManualTrigger(ctx, interval, trigger, func(bool) { cb() })
		},
	}

	for name, testFunc := range tests {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)

		done := make(chan bool)
		var counter atomic.Int32

		stop := testFunc(ctx, func() {
			result := counter.Load()
			if result < 2 {
				result = counter.Add(1)
				if result == 2 {
					// done after 2 calls
					done <- true
				}
			}
		})

		// We expect the timer to stop after 2 calls to the callback function
		select {
		case <-done:
			result := counter.Load()
			if result != 2 {
				t.Errorf("failure (%s) - expected to run callback exactly 2 times, it run %d times",
					name, result)
			}
		case <-ctx.Done():
			// Timeout
			t.Errorf("timeout (%s) - periodiccaller not working", name)
		}

		cancel()
		stop()
	}
}

// TestPeriodicCallerCancellation tests the cancellation functionality for all
// exported periodiccaller functions
func TestPeriodicCallerCancellation(t *testing.T) {
	// goroutine leak detector, see https://github.com/uber-go/goleak
	defer goleak.VerifyNone(t)
	interval := 1 * time.Millisecond
	trigger := make(chan bool)

	tests := map[string]func(context.Context, func()) func(){
		"Start": func(ctx context.Context, cb func()) func() {
			return Start(ctx, interval, cb)
		},
		"StartWithJitter": func(ctx context.Context, cb func()) func() {
			return StartWithJitter(ctx, interval, 0.2, cb)
		},
		"StartWithManualTrigger": func(ctx context.Context, cb func()) func() {
			return StartWithManualTrigger(ctx, interval, trigger, func(bool) { cb() })
		},
	}

	for name, testFunc := range tests {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)

		executions := make(chan struct{}, 20)
		stop := testFunc(ctx, func() {
			executions <- struct{}{}
		})

		// wait until timeout occurred
		<-ctx.Done()

		// give callback time to execute, if cancellation didn't work
		time.Sleep(10 * time.Millisecond)

		if len(executions) == 0 {
			t.Errorf("failure (%s) - periodiccaller never called", name)
		} else if len(executions) > 11 {
			t.Errorf("failure (%s) - cancellation not working", name)
		}

		cancel()
		stop()
	}
}

// TestPeriodicCallerManualTrigger tests periodic calling with manual trigger
func TestPeriodicCallerManualTrigger(t *testing.T) {
	// goroutine leak detector, see https://github.com/uber-go/goleak
	defer goleak.VerifyNone(t)
	// Number of manual triggers
	numTrigger := 5
	// This should be something larger than time taken to execute triggers
	interval := 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), interval)
	defer cancel()

	var counter atomic.Int32
	trigger := make(chan bool)
	done := make(chan bool)

	stop := StartWithManualTrigger(ctx, interval, trigger, func(manualTrigger bool) {
		if !manualTrigger {
			t.Errorf("failure - manualTrigger should be true")
		}
		n := counter.Add(1)
		if n == int32(numTrigger) {
			done <- true
		}
	})
	defer stop()

	for i := 0; i < numTrigger; i++ {
		trigger <- true
	}
	<-done

	numExec := counter.Load()
	if int(numExec) != numTrigger {
		t.Errorf("failure - expected to run callback exactly %d times, it run %d times",
			numTrigger, numExec)
	}
}
