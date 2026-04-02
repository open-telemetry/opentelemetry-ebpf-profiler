// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Pdata holds the cache for the data used to generate the events reporters
// will export when handling OTLP data.
type Pdata struct {
	// ExtraSampleAttrProd is an optional hook point for adding custom
	// attributes to samples.
	ExtraSampleAttrProd samples.SampleAttrProducer

	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int

	// probeMetadata stores metadata for dynamically registered probe origins.
	probeMetadata map[libpf.Origin]samples.ProbeOriginMetadata
}

func New(samplesPerSecond int, extra samples.SampleAttrProducer) (*Pdata, error) {
	return &Pdata{
		samplesPerSecond:    samplesPerSecond,
		ExtraSampleAttrProd: extra,
		probeMetadata:       make(map[libpf.Origin]samples.ProbeOriginMetadata),
	}, nil
}

// RegisterProbeOrigin registers metadata for a custom probe origin.
func (p *Pdata) RegisterProbeOrigin(origin libpf.Origin, meta samples.ProbeOriginMetadata) {
	p.probeMetadata[origin] = meta
}

// Purge purges all the expired data
func (p *Pdata) Purge() {
}
