// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package receiverhelper // import "go.opentelemetry.io/ebpf-profiler/collector/receiverhelper"

import (
	"context"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/ebpf-profiler/collector/internal"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

func TestWithExecutableReporter(t *testing.T) {
	executableReporter := &executableReporterTest{}
	option := WithExecutableReporter(executableReporter)
	require.Equal(t, executableReporter, option.Apply(&internal.ControllerOption{}).ExecutableReporter)
}

func TestWithReporterFactory(t *testing.T) {
	reporterFactory := func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error) {
		return &reporterTest{}, nil
	}
	option := WithReporterFactory(reporterFactory)
	returnedFactory := option.Apply(&internal.ControllerOption{}).ReporterFactory
	require.Equal(t, reflect.ValueOf(reporterFactory).Pointer(), reflect.ValueOf(returnedFactory).Pointer())
}

// empty struct that implements the ExecutableReporter interface
type executableReporterTest struct{}

func (e *executableReporterTest) ReportExecutable(args *reporter.ExecutableMetadata) {}

// empty struct that implements the Reporter interface
type reporterTest struct{}

func (r *reporterTest) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	return nil
}

func (r *reporterTest) Start(ctx context.Context) error {
	return nil
}

func (r *reporterTest) Stop() {}
