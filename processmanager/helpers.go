// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// executableReporterStub is a stub to implement reporter.ExecutableReporter which is used
// as the reporter by default. This can be overridden on at processmanager creation time.
type executableReporterStub struct{}

// ReportExecutable satisfies the reporter.ExecutableReporter interface.
func (er executableReporterStub) ReportExecutable(args *reporter.ExecutableMetadata) {
}

var _ reporter.ExecutableReporter = executableReporterStub{}

// traceReporterStub is a stub to implement reporter.TraceReporter which is used
// as the reporter by default. This can be overridden on at processmanager creation time.
type traceReporterStub struct{}

// ReportTraceEvent satisfies the reporter.TraceReporter interface.
func (tr traceReporterStub) ReportTraceEvent(_ *libpf.Trace, _ *samples.TraceEventMeta) error {
	return nil
}

var _ reporter.TraceReporter = traceReporterStub{}
