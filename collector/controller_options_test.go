// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package collector // import "go.opentelemetry.io/ebpf-profiler/collector"

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/consumer/xconsumer"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
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

func TestWithProcessMetaEnricher(t *testing.T) {
	// Simulate a /proc/<pid>/ directory with a loginuid file.
	procBase := t.TempDir() + "/"
	require.NoError(t, os.WriteFile(filepath.Join(procBase, "loginuid"), []byte("1000\n"), 0600))

	loginUIDEnricher := process.MetaEnricherFunc(func(procBase string, meta *process.Meta) {
		data, err := os.ReadFile(filepath.Join(procBase, "loginuid"))
		if err != nil {
			return
		}
		if meta.ExtraMeta == nil {
			meta.ExtraMeta = make(map[libpf.String]string)
		}
		meta.ExtraMeta[libpf.Intern("process.loginuid")] = strings.TrimSpace(string(data))
	})

	opt := WithProcessMetaEnricher(loginUIDEnricher)
	result := opt.apply(&controllerOption{})
	require.Len(t, result.processMetaEnrichers, 1)

	meta := &process.Meta{}
	result.processMetaEnrichers[0].EnrichMeta(procBase, meta)
	require.Equal(t, "1000", meta.ExtraMeta[libpf.Intern("process.loginuid")])
}

func TestWithReporterFactory(t *testing.T) {
	reporterFactory := func(cfg *reporter.Config, nextConsumer xconsumer.Profiles) (reporter.Reporter, error) {
		return nil, nil
	}
	option := WithReporterFactory(reporterFactory)
	require.Equal(
		t,
		reflect.ValueOf(reporterFactory).Pointer(),
		reflect.ValueOf(option.apply(&controllerOption{}).reporterFactory).Pointer())
}
