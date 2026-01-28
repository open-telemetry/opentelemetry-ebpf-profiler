// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"math/rand/v2"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

// AddJitter adds +/- jitter (jitter is [0..1]) to baseDuration
func AddJitter(baseDuration time.Duration, jitter float64) time.Duration {
	if jitter < 0.0 || jitter > 1.0 {
		log.Errorf("Jitter (%f) out of range [0..1].", jitter)
		return baseDuration
	}
	//nolint:gosec
	result := time.Duration((1 + jitter - 2*jitter*rand.Float64()) * float64(baseDuration))
	// Clamp to minimum 1ns to prevent panic in time.Ticker.Reset with d <= 0.
	// With jitter close to 1.0, float arithmetic can produce values that truncate to 0.
	if result < 1 {
		return 1
	}
	return result
}
