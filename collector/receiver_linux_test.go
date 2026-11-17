// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
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

func TestReceiverShutdownUnloadsProbes(t *testing.T) {
	mp := &mockProbe{}

	c := &profilesReceiver{
		opts:   &controllerOption{},
		probes: []tracer.Probe{mp},
	}

	if err := c.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if mp.unloadCalls != 1 {
		t.Errorf("Unload called %d times, want 1", mp.unloadCalls)
	}
}

type nonProbeExtension struct{}

func (e *nonProbeExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *nonProbeExtension) Shutdown(_ context.Context) error                { return nil }

func TestReceiverEnableProbesErrors(t *testing.T) {
	probeID := component.MustNewIDWithName("probe", "a")
	plainID := component.MustNewIDWithName("plain", "b")
	missingID := component.MustNewIDWithName("missing", "c")
	host := &mockHost{extensions: map[component.ID]component.Component{
		probeID: &mockExtension{probe: &mockProbe{}},
		plainID: &nonProbeExtension{},
	}}

	for _, tt := range []struct {
		name    string
		probes  []component.ID
		wantErr string
	}{
		{name: "no probes configured"},
		{name: "missing extension", probes: []component.ID{missingID}, wantErr: "not found"},
		{name: "not a ProbeExtension", probes: []component.ID{plainID},
			wantErr: "does not implement ProbeExtension"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			r := &profilesReceiver{
				cfg:  &config.Config{Probes: tt.probes},
				opts: &controllerOption{},
			}
			err := r.enableProbes(t.Context(), host)
			if tt.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
