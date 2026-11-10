// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Pdata holds the cache for the data used to generate the events reporters
// will export when handling OTLP data.
type Pdata struct {
	// ExtraSampleAttrProd is an optional hook point for adding custom
	// attributes to samples.
	ExtraSampleAttrProd samples.SampleAttrProducer
}

func New(extra samples.SampleAttrProducer) (*Pdata, error) {
	return &Pdata{
		ExtraSampleAttrProd: extra,
	}, nil
}

// Purge purges all the expired data
func (p *Pdata) Purge() {
}
