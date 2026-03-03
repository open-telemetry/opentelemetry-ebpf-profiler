//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package linux // import "go.opentelemetry.io/ebpf-profiler/internal/linux"

import (
	"fmt"
	"runtime"
)

// GetCurrentKernelVersion returns an error for OS other than linux.
func GetCurrentKernelVersion() (_, _, _ uint32, err error) {
	return 0, 0, 0, fmt.Errorf("kernel version detection is not supported on %s",
		runtime.GOOS)
}
