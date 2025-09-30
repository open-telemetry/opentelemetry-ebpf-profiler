// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

func TestWithExecutableReporter(t *testing.T) {
	executableReporter := &executableReporterTest{}
	option := WithExecutableReporter(executableReporter)
	require.Equal(t, executableReporter, option.apply(&controllerOption{}).executableReporter)
}

// empty struct that implements the ExecutableReporter interface
type executableReporterTest struct{}

func (e *executableReporterTest) ReportExecutable(args *reporter.ExecutableMetadata) {}

func TestWithOnShutdown(t *testing.T) {
	onShutdown := func() error { return nil }
	option := WithOnShutdown(onShutdown)
	require.Equal(
		t,
		reflect.ValueOf(onShutdown).Pointer(),
		reflect.ValueOf(option.apply(&controllerOption{}).onShutdown).Pointer())
}
