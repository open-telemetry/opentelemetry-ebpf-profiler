// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package offcpu // import "go.opentelemetry.io/ebpf-profiler/probes/offcpu"

import (
	"context"

	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// offCPUExtension is an OTel Collector extension that exposes a tracer.Probe
// for use by the ebpf_profiler receiver.
type offCPUExtension struct {
	p *probe
}

func (e *offCPUExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *offCPUExtension) Shutdown(_ context.Context) error                { return nil }

// Probe returns the tracer.Probe that this extension provides.
func (e *offCPUExtension) Probe() tracer.Probe { return e.p }
