// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package internal

import (
	"context"
	"testing"

	"go.opentelemetry.io/collector/component"

	internalcontroller "go.opentelemetry.io/ebpf-profiler/internal/controller"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type mockProbe struct {
	unloadCalls int
}

func (m *mockProbe) Load(_ context.Context, _ tracer.ProbeRegistrar, _ *tracer.ProbeContext) error {
	return nil
}

func (m *mockProbe) Unload() error {
	m.unloadCalls++
	return nil
}

type mockExtension struct {
	probe *mockProbe
}

func (e *mockExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *mockExtension) Shutdown(_ context.Context) error                { return nil }
func (e *mockExtension) Probe() tracer.Probe                             { return e.probe }

type mockHost struct {
	extensions map[component.ID]component.Component
}

func (h *mockHost) GetExtensions() map[component.ID]component.Component {
	return h.extensions
}

func TestControllerShutdownUnloadsProbes(t *testing.T) {
	mp := &mockProbe{}

	c := &Controller{
		ctlr:   internalcontroller.New(&internalcontroller.Config{}),
		probes: []tracer.Probe{mp},
	}

	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if mp.unloadCalls != 1 {
		t.Errorf("Unload called %d times, want 1", mp.unloadCalls)
	}
}
