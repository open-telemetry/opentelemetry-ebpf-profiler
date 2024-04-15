/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package interpreter

import (
	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/process"
	"github.com/elastic/otel-profiling-agent/metrics"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/tpbase"
)

// InstanceStubs provides empty implementations of Instance hooks that are
// not mandatory for a Instance implementation.
type InstanceStubs struct {
}

func (is *InstanceStubs) SynchronizeMappings(EbpfHandler, reporter.SymbolReporter, process.Process,
	[]process.Mapping) error {
	return nil
}

func (is *InstanceStubs) UpdateTSDInfo(EbpfHandler, libpf.PID, tpbase.TSDInfo) error {
	return nil
}

func (is *InstanceStubs) Symbolize(reporter.SymbolReporter, *host.Frame, *libpf.Trace) error {
	return ErrMismatchInterpreterType
}

func (is *InstanceStubs) GetAndResetMetrics() ([]metrics.Metric, error) {
	return []metrics.Metric{}, nil
}
