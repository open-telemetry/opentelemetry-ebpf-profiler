// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector

import (
	"context"
	"fmt"
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
)

// dummyReporter is a no-op reporter for testing.
type dummyReporter struct{}

func (d *dummyReporter) Start(context.Context) error                                  { return fmt.Errorf("dummy error") }
func (d *dummyReporter) Stop()                                                        {}
func (d *dummyReporter) ReportTraceEvent(*libpf.Trace, *samples.TraceEventMeta) error { return nil }
func (d *dummyReporter) RegisterProbeOrigin(libpf.Origin, samples.ProbeOriginMetadata) error {
	return nil
}

// TestStartErrorMode tests the error_mode config option on controller Start().
// dummyReporter.Start() always returns an error to simulate startup failure.
func TestStartErrorMode(t *testing.T) {
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
