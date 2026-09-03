//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// SynchronizeProcessForTest prepares a process for unwinding in integration tests.
func (t *Tracer) SynchronizeProcessForTest(pid, tid libpf.PID) {
	t.processManager.SynchronizeProcess(process.New(pid, tid))
}
