// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"math/rand/v2"
	"time"
	"unsafe"

	log "github.com/sirupsen/logrus"
)

// AddJitter adds +/- jitter (jitter is [0..1]) to baseDuration
func AddJitter(baseDuration time.Duration, jitter float64) time.Duration {
	if jitter < 0.0 || jitter > 1.0 {
		log.Errorf("Jitter (%f) out of range [0..1].", jitter)
		return baseDuration
	}
	//nolint:gosec
	return time.Duration((1 + jitter - 2*jitter*rand.Float64()) * float64(baseDuration))
}

// SliceFromPointer converts a Go struct pointer to []byte to read data into
// data must be a non-nil pointer to a struct
func SliceFromPointer[T any](data *T) []byte {
	return unsafe.Slice(
		(*byte)(unsafe.Pointer(data)),
		int(unsafe.Sizeof(*data)),
	)
}

// SliceFromSlice converts a Go slice to []byte to read data into
func SliceFromSlice[T any](data []T) []byte {
	if len(data) == 0 {
		return nil
	}
	return unsafe.Slice(
		(*byte)(unsafe.Pointer(&data[0])),
		len(data)*int(unsafe.Sizeof(data[0])),
	)
}
