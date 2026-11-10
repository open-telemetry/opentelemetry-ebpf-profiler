// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package heap // import "go.opentelemetry.io/ebpf-profiler/probes/heap"

import (
	"context"

	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// heapExtension is an OTel Collector extension that exposes a tracer.Probe
// for use by the ebpf_profiler receiver.
type heapExtension struct {
	p tracer.Probe
}

func (e *heapExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *heapExtension) Shutdown(_ context.Context) error                { return nil }

// Probe returns the tracer.Probe that this extension provides.
func (e *heapExtension) Probe() tracer.Probe { return e.p }
