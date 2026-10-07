// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/exporter/otlpexporter"
	"go.opentelemetry.io/collector/exporter/xexporter"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	"google.golang.org/grpc"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// otlpExporterReporter sends the profiles built by reporter.CollectorReporter
// through the collector's otlpexporter and ties the exporter lifecycle to the reporter.
type otlpExporterReporter struct {
	*reporter.CollectorReporter
	exporter xexporter.Profiles
}

func (r *otlpExporterReporter) Start(ctx context.Context) error {
	if err := r.exporter.Start(ctx, componenttest.NewNopHost()); err != nil {
		return err
	}
	return r.CollectorReporter.Start(ctx)
}

func (r *otlpExporterReporter) Stop() {
	r.CollectorReporter.Stop()
	_ = r.exporter.Shutdown(context.Background())
}

// newOTLPReporterFactory returns a reporter factory that exports profiles to
// endpoint with the otlpexporter, configured like the deprecated reporter.NewOTLP.
// The receiver's next consumer is ignored as the exporter takes its place.
func newOTLPReporterFactory(endpoint string, disableTLS bool,
) func(*reporter.Config, xconsumer.Profiles) (reporter.Reporter, error) {
	return func(cfg *reporter.Config, _ xconsumer.Profiles) (reporter.Reporter, error) {
		factory := otlpexporter.NewFactory().(xexporter.Factory)

		expCfg := factory.CreateDefaultConfig().(*otlpexporter.Config)
		expCfg.ClientConfig.Endpoint = endpoint
		expCfg.ClientConfig.TLS.Insecure = disableTLS
		expCfg.ClientConfig.TLS.MinVersion = "1.3"
		expCfg.ClientConfig.WaitForReady = true
		expCfg.TimeoutConfig.Timeout = 5 * time.Second
		// NewOTLP sends each report synchronously and drops it on failure.
		expCfg.QueueConfig = configoptional.None[exporterhelper.QueueBatchConfig]()
		expCfg.RetryConfig.Enabled = false

		exp, err := factory.CreateProfiles(context.Background(),
			exportertest.NewNopSettings(factory.Type()), expCfg)
		if err != nil {
			return nil, err
		}

		rep, err := reporter.NewCollector(cfg, exp)
		if err != nil {
			return nil, err
		}
		return &otlpExporterReporter{CollectorReporter: rep, exporter: exp}, nil
	}
}

// ExampleWithReporterFactory exports profiles with the collector's otlpexporter:
// https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/otlpexporter
func ExampleWithReporterFactory() {
	createProfiles := BuildProfilesReceiver(
		WithReporterFactory(newOTLPReporterFactory("localhost:4317", true)),
	)
	_ = createProfiles
}

type profilesServer struct {
	pprofileotlp.UnimplementedGRPCServer
	received chan pprofileotlp.ExportRequest
}

func (s *profilesServer) Export(_ context.Context, req pprofileotlp.ExportRequest,
) (pprofileotlp.ExportResponse, error) {
	s.received <- req
	return pprofileotlp.NewExportResponse(), nil
}

func TestWithReporterFactoryOTLPExporter(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	srv := grpc.NewServer()
	backend := &profilesServer{received: make(chan pprofileotlp.ExportRequest, 1)}
	pprofileotlp.RegisterGRPCServer(srv, backend)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	option := WithReporterFactory(newOTLPReporterFactory(lis.Addr().String(), true))
	rep, err := option.apply(&controllerOption{}).reporterFactory(&reporter.Config{
		Name:             "test",
		SamplesPerSecond: 20,
		ReportInterval:   50 * time.Millisecond,
	}, nil)
	require.NoError(t, err)

	require.NoError(t, rep.Start(t.Context()))
	t.Cleanup(rep.Stop)

	frames := make(libpf.Frames, 0, 1)
	frames.Append(&libpf.Frame{
		Type:            libpf.KernelFrame,
		AddressOrLineno: 0xef,
		FunctionName:    libpf.Intern("func1"),
	})
	require.NoError(t, rep.ReportTraceEvent(&libpf.Trace{Frames: frames}, &samples.TraceEventMeta{
		Timestamp: libpf.UnixTime64(time.Now().UnixNano()),
		PID:       1,
		ProfileType: &samples.TypeMetadata{
			PeriodType: "cpu",
			PeriodUnit: "nanoseconds",
			SampleType: "samples",
			SampleUnit: "count",
		},
	}))

	select {
	case req := <-backend.received:
		require.Equal(t, 1, req.Profiles().SampleCount())
	case <-time.After(10 * time.Second):
		t.Fatal("no profiles received by the OTLP backend")
	}
}
