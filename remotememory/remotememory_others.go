//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package remotememory // import "go.opentelemetry.io/ebpf-profiler/remotememory"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func procMemRemoteMemory(rootFsPath string, pid libpf.PID) func(p []byte, off int64) (int, error) {
	return func(p []byte, off int64) (int, error) {
		return 0, nil
	}
}

func processVMRemoteMemory(pid libpf.PID) func(p []byte, off int64) (int, error) {
	return func(p []byte, off int64) (int, error) {
		return 0, nil
	}
}
