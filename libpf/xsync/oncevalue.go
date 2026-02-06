// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package xsync // import "go.opentelemetry.io/ebpf-profiler/libpf/xsync"

import (
	"sync"
	"sync/atomic"
)

// OnceValue provides lazy initialization with error handling.
// It wraps sync.OnceValues to provide a convenient API that caches
// both the computed value and any error from the init function.
type OnceValue[T any] struct {
	fn atomic.Pointer[func() (T, error)]
}

// GetOrInit returns the value, initializing it exactly once using the provided init function.
//
// Multiple concurrent calls are safe - only one will execute the init function.
func (o *OnceValue[T]) GetOrInit(init func() (T, error)) (T, error) {
	fn := o.fn.Load()
	if fn == nil {
		newFn := sync.OnceValues(init)
		if !o.fn.CompareAndSwap(nil, &newFn) {
			fn = o.fn.Load()
		} else {
			fn = &newFn
		}
	}
	return (*fn)()
}

// Get returns the cached value if already initialized and error-free, nil otherwise.
func (o *OnceValue[T]) Get() *T {
	fn := o.fn.Load()
	if fn == nil {
		return nil
	}
	val, err := (*fn)()
	if err != nil {
		return nil
	}
	return &val
}
