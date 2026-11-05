// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package kprobe // import "go.opentelemetry.io/ebpf-profiler/probes/kprobe"

import (
	"context"

	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// kprobeExtension implements collector.ProbeExtension: it is an OTel Collector
// extension that exposes a tracer.Probe for use by the ebpf_profiler receiver.
type kprobeExtension struct {
	p *probe
}

func (e *kprobeExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *kprobeExtension) Shutdown(_ context.Context) error                { return nil }

// Probe returns the tracer.Probe that this extension provides.
// The receiver calls this after Start and passes the result to tracer.Enable.
func (e *kprobeExtension) Probe() tracer.Probe { return e.p }
