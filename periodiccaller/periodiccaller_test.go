// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package periodiccaller allows periodic calls of functions.
package periodiccaller

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchStackRecords returns all stacks from all Go routines.
func fetchStackRecords(t *testing.T) []runtime.StackRecord {
	t.Helper()

	// Explicit GC call to make sure stopped Go routines are cleaned up.
	runtime.GC()

	var n int
	var ok bool
	sr := make([]runtime.StackRecord, os.Getpagesize())
	for {
		n, ok = runtime.GoroutineProfile(sr)
		if !ok {
			// Grow sr
			sr = append(sr, make([]runtime.StackRecord, os.Getpagesize())...)
			continue
		}
		return sr[:n]
	}
}

// isSelfOrRuntime returns true if stack is from self or a Go runtime internal stack.
func isSelfOrRuntime(t *testing.T, stack *[32]uintptr, self string) bool {
	t.Helper()
	isRuntimeOnly := true
	for _, pc := range stack {
		f := runtime.FuncForPC(pc)
		if f != nil {
			funcName := f.Name()

			if funcName == self {
				return true
			}
			// Go runtime specific filters
			if !strings.HasPrefix(funcName, "runtime.") &&
				!strings.HasPrefix(funcName, "runtime/") &&
				!strings.HasPrefix(funcName, "testing.") &&
				!strings.HasPrefix(funcName, "internal/runtime") &&
				funcName != "main.main" {
				isRuntimeOnly = false
			}
		}
	}
	return isRuntimeOnly
}

// checkForGoRoutineLeaks calls panic if Go routines are still running
func checkForGoRoutineLeaks(t *testing.T) {
	t.Helper()

	rpc := make([]uintptr, 1)
	m := runtime.Callers(1, rpc)
	if m < 1 {
		t.Fatal("could not determine selfFrame")
	}
	selfFrame, _ := runtime.CallersFrames(rpc).Next()
	sr := fetchStackRecords(t)

	leakedGoRoutines := make([]int, 0)
	for i := range sr {
		if isSelfOrRuntime(t, &sr[i].Stack0, selfFrame.Func.Name()) {
			continue
		}
		leakedGoRoutines = append(leakedGoRoutines, i)
	}

	if len(leakedGoRoutines) != 0 {
		for _, j := range leakedGoRoutines {
			for _, k := range sr[j].Stack() {
				t.Logf("%s\n", runtime.FuncForPC(k).Name())
			}
			t.Log("")
		}
		panic(fmt.Sprintf("Got %d leaked Go routines", len(leakedGoRoutines)))
	}
}

func TestCheckForGoRoutineLeaks(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		wg.Done()
		// Block further processing.
		<-ctx.Done()
	}()

	// Enforce wait to make sure the Go routine exists.
	wg.Wait()

	defer func() {
		r := recover()
		// checkForGoRoutineLeaks is expected to panic.
		require.NotNil(t, r)
	}()

	checkForGoRoutineLeaks(t)
}

// TestPeriodicCaller tests periodic calling for all exported periodiccaller functions
func TestPeriodicCaller(t *testing.T) {
	defer checkForGoRoutineLeaks(t)
	interval := 10 * time.Millisecond
	trigger := make(chan bool)

	tests := map[string]func(context.Context, func()){
		"Start": func(ctx context.Context, cb func()) {
			Start(ctx, interval, cb)
		},
		"StartWithManualTrigger": func(ctx context.Context, cb func()) {
			StartWithManualTrigger(ctx, interval, trigger, func(bool) bool {
				cb()
				return true
			})
		},
	}

	for name, testFunc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 1*time.Second)

			done := make(chan bool)
			var counter atomic.Int32

			testFunc(ctx, func() {
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
				assert.Equal(t, int32(2), result)
			case <-ctx.Done():
				// Timeout
				assert.Failf(t, "timeout (%s) - periodiccaller not working", name)
			}

			cancel()
		})
	}
}

// TestStartTracked verifies that the tracked goroutine exits after
// cancellation, and that no callbacks run afterwards.
func TestStartTracked(t *testing.T) {
	defer checkForGoRoutineLeaks(t)
	interval := 1 * time.Millisecond

	ctx, cancel := context.WithCancel(t.Context())
	var counter atomic.Int32
	var wg sync.WaitGroup

	StartTracked(ctx, &wg, interval, func() {
		counter.Add(1)
	})

	require.Eventually(t, func() bool { return counter.Load() >= 3 },
		10*time.Second, time.Millisecond, "callback was not called")

	cancel()
	exited := make(chan struct{})
	go func() {
		wg.Wait()
		close(exited)
	}()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		assert.Fail(t, "timeout - tracked goroutine did not exit after cancellation")
	}

	// No callbacks may run after the goroutine exited.
	count := counter.Load()
	time.Sleep(20 * time.Millisecond)
	assert.Equal(t, count, counter.Load())
}

// TestPeriodicCallerCancellation tests the cancellation functionality for all
// exported periodiccaller functions
func TestPeriodicCallerCancellation(t *testing.T) {
	defer checkForGoRoutineLeaks(t)
	interval := 1 * time.Millisecond
	trigger := make(chan bool)

	tests := map[string]func(context.Context, func()){
		"Start": func(ctx context.Context, cb func()) {
			Start(ctx, interval, cb)
		},
		"StartWithManualTrigger": func(ctx context.Context, cb func()) {
			StartWithManualTrigger(ctx, interval, trigger, func(bool) bool {
				cb()
				return true
			})
		},
	}

	for name, testFunc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)

			executions := make(chan struct{}, 20)
			testFunc(ctx, func() {
				executions <- struct{}{}
			})

			// wait until timeout occurred
			<-ctx.Done()

			// give callback time to execute, if cancellation didn't work
			time.Sleep(10 * time.Millisecond)

			assert.NotEmpty(t, executions)
			assert.Less(t, len(executions), 12)

			cancel()
		})
	}
}

// TestPeriodicCallerManualTrigger tests periodic calling with manual trigger
func TestPeriodicCallerManualTrigger(t *testing.T) {
	defer checkForGoRoutineLeaks(t)
	// Number of manual triggers
	numTrigger := int32(5)
	// This should be something larger than time taken to execute triggers
	interval := 10 * time.Second
	ctx, cancel := context.WithTimeout(t.Context(), interval)
	defer cancel()

	var counter atomic.Int32
	trigger := make(chan bool)
	done := make(chan bool)

	StartWithManualTrigger(ctx, interval, trigger, func(manualTrigger bool) bool {
		require.True(t, manualTrigger)
		n := counter.Add(1)
		if n == int32(numTrigger) {
			done <- true
		}
		return true
	})

	for range numTrigger {
		trigger <- true
	}
	<-done
	assert.Equal(t, counter.Load(), numTrigger)
}

// TestPeriodicCallerSelfStop tests periodic calling with self stoppage
func TestPeriodicCallerSelfStop(t *testing.T) {
	defer checkForGoRoutineLeaks(t)
	// Number of iterations we allow the callback to be called
	numIters := int32(5)

	// This should be something larger than time taken to execute this test
	timeout := time.After(10 * time.Second)

	var counter atomic.Int32
	trigger := make(chan bool)
	done := make(chan bool, 1)

	StartWithManualTrigger(t.Context(), 1*time.Millisecond, trigger,
		func(manualTrigger bool) bool {
			n := counter.Add(1)
			if n == int32(numIters) {
				done <- true
				return false
			}
			return true
		})

	select {
	case <-timeout:
		assert.Fail(t, "timeout - periodiccaller not working")
	case <-done:
	}

	assert.Equal(t, numIters, counter.Load())
}
