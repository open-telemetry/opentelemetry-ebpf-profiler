// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"errors"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// TracerMaps exposes loaded eBPF maps for reuse.
type TracerMaps map[string]*cebpf.Map

// Probe defines the interface that allows custom stack unwinding
// trigger points.
type Probe interface {
	// Load attaches a probe that triggers stack unwinding.
	// Returns the link and a reference to self to keep the probe alive.
	Load(libpf.Origin, TracerMaps, *SysConfigVars) (link.Link, error)

	// ReportMetadata provides the necessary metadata to report
	// the events of the Probe.
	ReportMetadata() *samples.TypeMetadata
}

// Enable lets the tracer call Load() on a custom probe and
// inform the reporter about the expected TypeMetadata.
func (t *Tracer) Enable(p Probe) error {
	// TODO: depends on https://github.com/open-telemetry/opentelemetry-ebpf-profiler/pull/1607
	return errors.New("not yet implemented")
}
