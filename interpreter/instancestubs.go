/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package interpreter

import (
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/host"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/metrics"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/process"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/reporter"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tpbase"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/util"
)

// InstanceStubs provides empty implementations of Instance hooks that are
// not mandatory for a Instance implementation.
type InstanceStubs struct {
}

func (is *InstanceStubs) SynchronizeMappings(EbpfHandler, reporter.SymbolReporter, process.Process,
	[]process.Mapping) error {
	return nil
}

func (is *InstanceStubs) UpdateTSDInfo(EbpfHandler, util.PID, tpbase.TSDInfo) error {
	return nil
}

func (is *InstanceStubs) Symbolize(reporter.SymbolReporter, *host.Frame, *libpf.Trace) error {
	return ErrMismatchInterpreterType
}

func (is *InstanceStubs) GetAndResetMetrics() ([]metrics.Metric, error) {
	return []metrics.Metric{}, nil
}
