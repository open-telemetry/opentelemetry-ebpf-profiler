// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interpreter // import "go.opentelemetry.io/ebpf-profiler/interpreter"

import (
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tpbase"
)

// ObserverStubs provides empty implementations of Observer hooks that are
// not mandatory for an Observer implementation.
type ObserverStubs struct {
}

func (os *ObserverStubs) Detach(EbpfHandler, libpf.PID) error {
	return nil
}

func (os *ObserverStubs) SynchronizeMappings(EbpfHandler, reporter.SymbolReporter, process.Process,
	[]process.Mapping) error {
	return nil
}

func (os *ObserverStubs) UpdateTSDInfo(EbpfHandler, libpf.PID, tpbase.TSDInfo) error {
	return nil
}

func (os *ObserverStubs) GetAndResetMetrics() ([]metrics.Metric, error) {
	return []metrics.Metric{}, nil
}

// InstanceStubs provides empty implementations of Instance hooks that are
// not mandatory for a Instance implementation.
type InstanceStubs struct {
	ObserverStubs
}

func (is *InstanceStubs) Symbolize(reporter.SymbolReporter, *host.Frame, *libpf.Trace) error {
	return ErrMismatchInterpreterType
}
