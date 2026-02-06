// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package xsync_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
)

func TestOnceValue(t *testing.T) {
	once := xsync.OnceValue[string]{}
	wg := sync.WaitGroup{}

	assert.Nil(t, once.Get())

	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			val, err := once.GetOrInit(func() (string, error) {
				time.Sleep(10 * time.Millisecond)
				return "success", nil
			})
			assert.NoError(t, err)
			assert.Equal(t, "success", val)
		}()
	}

	wg.Wait()
	assert.Equal(t, "success", *once.Get())
}

func TestOnceValueConcurrentInit(t *testing.T) {
	once := xsync.OnceValue[int]{}
	calls := atomic.Int32{}
	barrier := make(chan libpf.Void)
	wg := sync.WaitGroup{}

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-barrier // Block all goroutines to be ready
			val, err := once.GetOrInit(func() (int, error) {
				calls.Add(1)
				time.Sleep(10 * time.Millisecond)
				return 42, nil
			})
			assert.NoError(t, err)
			assert.Equal(t, 42, val)
		}()
	}

	close(barrier) // Start all at once
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load())
	assert.Equal(t, 42, *once.Get())
}
