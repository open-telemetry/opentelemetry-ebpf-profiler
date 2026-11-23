// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"go.opentelemetry.io/ebpf-profiler/collector/config"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// dummyReporter is a reporter whose Start always fails.
type dummyReporter struct{}

func (d *dummyReporter) Start(context.Context) error                                  { return errors.New("dummy error") }
func (d *dummyReporter) Stop()                                                        {}
func (d *dummyReporter) SetSnapshotSource(samples.SnapshotSource)                     {}
func (d *dummyReporter) ReportTraceEvent(*libpf.Trace, *samples.TraceEventMeta) error { return nil }

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

type nonProbeExtension struct{}

func (e *nonProbeExtension) Start(_ context.Context, _ component.Host) error { return nil }
func (e *nonProbeExtension) Shutdown(_ context.Context) error                { return nil }

type mockHost struct {
	extensions map[component.ID]component.Component
}

func (h *mockHost) GetExtensions() map[component.ID]component.Component {
	return h.extensions
}

// TestReceiverStartErrorMode checks that error_mode decides whether a failed
// Start reaches the collector.
func TestReceiverStartErrorMode(t *testing.T) {
	dummyFactory := func(_ *reporter.Config, _ xconsumer.Profiles) (reporter.Reporter, error) {
		return &dummyReporter{}, nil
	}

	for _, tt := range []struct {
		name      string
		errorMode config.ErrorMode
		wantErr   bool
	}{
		{
			name:      "propagate returns error",
			errorMode: config.PropagateError,
			wantErr:   true,
		},
		{
			name:      "ignore returns nil",
			errorMode: config.IgnoreError,
			wantErr:   false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig().(*config.Config)
			cfg.ErrorMode = tt.errorMode
			cfg.NoKernelVersionCheck = true

			typ, err := component.NewType("test")
			require.NoError(t, err)

			recv, err := BuildProfilesReceiver(
				WithReporterFactory(dummyFactory),
			)(
				t.Context(),
				receivertest.NewNopSettings(typ),
				cfg,
				consumertest.NewNop(),
			)
			require.NoError(t, err)

			err = recv.Start(t.Context(), componenttest.NewNopHost())
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestReceiverShutdownUnloadsProbes(t *testing.T) {
	mp := &mockProbe{}

	c := &profilesReceiver{
		opts:   &receiverOption{},
		probes: []tracer.Probe{mp},
	}

	require.NoError(t, c.Shutdown(context.Background()))
	require.Equal(t, 1, mp.unloadCalls)
}

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
				opts: &receiverOption{},
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
