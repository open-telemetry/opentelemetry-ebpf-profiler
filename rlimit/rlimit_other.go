//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package rlimit // import "go.opentelemetry.io/ebpf-profiler/rlimit"

import (
	"fmt"
	"runtime"
)

// MaximizeMemlock is the stub implementation, allowing to compile the rlimit
// package on non-linux systems, always failing at runtime with an error if used.
func MaximizeMemlock() (func(), error) {
	return nil, fmt.Errorf("unsupported os %s", runtime.GOOS)
}
