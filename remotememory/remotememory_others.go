//go:build !linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package remotememory // import "go.opentelemetry.io/ebpf-profiler/remotememory"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func NewProcessVirtualMemory(pid libpf.PID, rootFsPath string) (RemoteMemory, error) {
	return RemoteMemory{}, nil
}
