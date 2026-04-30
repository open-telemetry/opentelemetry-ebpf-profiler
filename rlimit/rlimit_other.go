// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build !linux

package rlimit // import "go.opentelemetry.io/ebpf-profiler/rlimit"

import "errors"

// MaximizeMemlock is a no-op on non-Linux platforms.
func MaximizeMemlock() (func(), error) {
	return nil, errors.New("rlimit manipulation is not supported on this platform")
}
