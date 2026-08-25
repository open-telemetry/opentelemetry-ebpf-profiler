// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package uprobe // import "go.opentelemetry.io/ebpf-profiler/probes/uprobe"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// uprobeExtension is an OTel Collector extension that exposes a tracer.Probe
// for use by the ebpf_profiler receiver.
type uprobeExtension struct {
	p tracer.Probe
}

func (e *uprobeExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *uprobeExtension) Shutdown(_ context.Context) error                { return nil }

// Probe returns the tracer.Probe that this extension provides.
func (e *uprobeExtension) Probe() tracer.Probe { return e.p }
