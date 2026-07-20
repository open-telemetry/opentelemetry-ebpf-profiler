// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package nnop implements a no operation custom probe as an example.
package noop // import "go.opentelemetry.io/ebpf-profiler/probes/noop"

import (
	"errors"

	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type noopProbe struct{}

func New(_ any) (tracer.Probe, error) {
	probe := &noopProbe{}
	return probe, nil
}

func (o *noopProbe) Load(originID uint16, maps tracer.TracerMaps, systemVars *tracer.SysConfigVars) (link.Link, error) {
	// TODO: depends on https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/1607
	return nil, errors.New("not yet implemented")
}

func (o *noopProbe) ReportMetadata() *samples.TypeMetadata {
	return &samples.TypeMetadata{
		SampleType: "noop",
		SampleUnit: "none",
	}
}
