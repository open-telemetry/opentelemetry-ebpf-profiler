/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package libpf

import (
	"context"
	"fmt"
	"math/rand/v2"
	"os"
	"reflect"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// WriteTempFile writes a data buffer to a temporary file on the filesystem. It
// is the callers responsibility to clean up that file again. The function returns
// the filename if successful.
func WriteTempFile(data []byte, directory, prefix string) (string, error) {
	file, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := file.Write(data); err != nil {
		return "", fmt.Errorf("failed to write data to temporary file: %w", err)
	}
	if err := file.Sync(); err != nil {
		return "", fmt.Errorf("failed to synchronize file data: %w", err)
	}
	return file.Name(), nil
}

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
