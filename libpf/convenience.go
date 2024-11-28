// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"context"
	"math/rand/v2"
	"reflect"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// SleepWithJitter sleeps for baseDuration +/- jitter (jitter is [0..1])
func SleepWithJitter(baseDuration time.Duration, jitter float64) {
	time.Sleep(AddJitter(baseDuration, jitter))
}

// SleepWithJitterAndContext blocks for duration +/- jitter (jitter is [0..1]) or until ctx
// is canceled.
func SleepWithJitterAndContext(ctx context.Context, duration time.Duration, jitter float64) error {
	tick := time.NewTicker(AddJitter(duration, jitter))
	defer tick.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-tick.C:
		return nil
	}
}

// AddJitter adds +/- jitter (jitter is [0..1]) to baseDuration
func AddJitter(baseDuration time.Duration, jitter float64) time.Duration {
	if jitter < 0.0 || jitter > 1.0 {
		log.Errorf("Jitter (%f) out of range [0..1].", jitter)
		return baseDuration
	}
	//nolint:gosec
	return time.Duration((1 + jitter - 2*jitter*rand.Float64()) * float64(baseDuration))
}

// SliceFrom converts a Go struct pointer or slice to []byte to read data into
func SliceFrom(data any) []byte {
	var s []byte
	val := reflect.ValueOf(data)
	switch val.Kind() {
	case reflect.Slice:
		if val.Len() != 0 {
			e := val.Index(0)
			addr := e.Addr().UnsafePointer()
			l := val.Len() * int(e.Type().Size())
			s = unsafe.Slice((*byte)(addr), l)
		}
	case reflect.Ptr:
		e := val.Elem()
		addr := e.Addr().UnsafePointer()
		l := int(e.Type().Size())
		s = unsafe.Slice((*byte)(addr), l)
	default:
		panic("invalid type")
	}
	return s
}
