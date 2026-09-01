//go:build host_integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// expectedResourceAttrs is the subset of attributes published by
// init_process_context() in processctx_lib.c that this test asserts on.
var expectedResourceAttrs = map[string]string{
	"service.name":                "my-service",
	"service.version":             "4.5.6",
	"service.instance.id":         "123d8444-2c7e-46e3-89f6-6217880f7123",
	"deployment.environment.name": "prod",
	"telemetry.sdk.language":      "c",
	"telemetry.sdk.version":       "1.2.3",
	"telemetry.sdk.name":          "example_ctx.c",
	"resource.key1":               "resource.value1",
	"resource.key2":               "resource.value2",
}

// expectedThreadLabels is what update_thread_context() in testdata/processctx_lib.c encodes,
// resolved through the attribute_key_map published with the process context.
var expectedThreadLabels = map[string]string{
	"http_route":  "some_endpoint",
	"http_method": "GET",
	"user_id":     "some_user_id",
}

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

// capturedEvent pairs the TraceEventMeta HandleTrace resolved with the trace's
// custom labels, which the tracer decoded from thread-local storage.
type capturedEvent struct {
	meta   *samples.TraceEventMeta
	labels map[libpf.String]libpf.String
}

// captureReporter exposes the reported trace events.
type captureReporter struct {
	eventCh chan capturedEvent
}

func newCaptureReporter() *captureReporter {
	return &captureReporter{eventCh: make(chan capturedEvent, 64)}
}

func (r *captureReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	r.eventCh <- capturedEvent{meta: meta, labels: trace.CustomLabels}
	return nil
}

var _ reporter.TraceReporter = (*captureReporter)(nil)

func isRoot() bool {
	return os.Geteuid() == 0
}

func Test_ProcessContext(t *testing.T) {
	if !isRoot() {
		t.Skip("root privileges required")
	}

	curDir, err := os.Getwd()
	require.NoError(t, err)
	exeDir := filepath.Join(curDir, "testdata")
	allCPUs := []int{}

	tests := map[string]struct {
		exeName string
		args    []string
		env     []string
	}{
		"glibc_exe": {exeName: "processctx_exe_glibc"},
		// Publishes the process context after a delay, so the profiler discovers
		// the PID before the publication and the prctl monitor must trigger a
		// resync to pick up the OTEL_CTX mapping.
		"glibc_exe_delayed_publish": {
			exeName: "processctx_exe_glibc",
			env:     []string{"OTEL_PROCESS_CTX_PUBLISH_DELAY_MS=200"},
		},
		"musl_exe": {exeName: "processctx_exe_musl"},

		// Executables linking a shared library at startup. The library accesses
		// its own TLS symbol, exercising the general-dynamic (default and GNU
		// dialects), initial-exec and local-dynamic models.
		"glibc_lib":     {exeName: "processctx_lib_glibc"},
		"musl_lib":      {exeName: "processctx_lib_musl"},
		"glibc_lib_gnu": {exeName: "processctx_lib_glibc_gnu"},
		"musl_lib_gnu":  {exeName: "processctx_lib_musl_gnu"},
		"glibc_lib_ie":  {exeName: "processctx_lib_glibc_ie"},
		"musl_lib_ie":   {exeName: "processctx_lib_musl_ie"},
		"glibc_lib_ld":  {exeName: "processctx_lib_glibc_ld"},
		"musl_lib_ld":   {exeName: "processctx_lib_musl_ld"},

		// dlopen'd libraries: the module is loaded after startup, exercising the
		// dynamic-TLS resolution path (DTV based) for both dialects.
		"glibc_dlopen":     {exeName: "processctx_dlopen_glibc", args: []string{filepath.Join(exeDir, "libprocessctx_glibc.so")}},
		"musl_dlopen":      {exeName: "processctx_dlopen_musl", args: []string{filepath.Join(exeDir, "libprocessctx_musl.so")}},
		"glibc_dlopen_gnu": {exeName: "processctx_dlopen_glibc", args: []string{filepath.Join(exeDir, "libprocessctx_glibc_gnu.so")}},
		"musl_dlopen_gnu":  {exeName: "processctx_dlopen_musl", args: []string{filepath.Join(exeDir, "libprocessctx_musl_gnu.so")}},

		// Non-PIE executable dlopen'ing a TLS-descriptor library. glibc
		// allocates the descriptor's tls_index on the brk heap, which for a
		// non-PIE process sits below 4 GiB, in the same range as a plausible
		// static TP-relative offset. On aarch64 only readTLSIndex's dereference
		// separates the two; on x86-64 the argument's sign already does.
		// The tunable disables the static TLS surplus, which glibc would
		// otherwise use for a module this small, making the descriptor static.
		"glibc_dlopen_nopie": {
			exeName: "processctx_dlopen_glibc_nopie",
			args:    []string{filepath.Join(exeDir, "libprocessctx_glibc.so")},
			env:     []string{"GLIBC_TUNABLES=glibc.rtld.optional_static_tls=0"},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			metrics.Start(noop.Meter{})

			log.SetLevel(slog.LevelDebug)
			rep := newCaptureReporter()
			trc, err := tracer.NewTracer(ctx, &tracer.Config{
				Intervals:              &mockIntervals{},
				InterpretersConfig:     interpreterconfig.AllInterpreters(),
				SamplesPerSecond:       20,
				ProbabilisticInterval:  100,
				ProbabilisticThreshold: 100,
				VerboseMode:            true,
				TraceReporter:          rep,
			})
			require.NoError(t, err)
			defer trc.Close()

			trc.StartPIDEventProcessor(ctx)
			require.NoError(t, trc.AttachTracer(allCPUs))

			t.Log("Attached tracer program")
			require.NoError(t, trc.EnableProfiling())
			require.NoError(t, trc.AttachSchedMonitor())
			require.NoError(t, trc.AttachPrctlMonitor())

			traceCh := make(chan *libpf.EbpfTrace)
			require.NoError(t, trc.StartMapMonitors(ctx, traceCh))

			// HandleTrace is what resolves the process context onto the meta
			// the reporter captures.
			go func() {
				for {
					select {
					case <-ctx.Done():
						return
					case trace := <-traceCh:
						if trace != nil {
							trc.HandleTrace(trace)
						}
					}
				}
			}()

			cmd := exec.CommandContext(ctx, filepath.Join(exeDir, tc.exeName), tc.args...)
			cmd.Stderr = os.Stderr
			if len(tc.env) > 0 {
				cmd.Env = append(os.Environ(), tc.env...)
			}
			require.NoError(t, cmd.Start())

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := cmd.Wait()
				select {
				case <-ctx.Done():
					t.Log("Test program cancelled (run complete)")
				default:
					// require.* must run on the test goroutine, so fail here
					// and cancel to unblock the main loop.
					t.Errorf("test program exited unexpectedly: %v", err)
					cancel()
				}
			}()

			timeout := time.NewTimer(10 * time.Second)
			defer timeout.Stop()

			// Tracked separately: a sample can land before the context is
			// published, or while update_thread_context() has the thread
			// context marked invalid, so neither implies the other.
			gotResource, gotLabels := false, false
		Loop:
			for {
				select {
				case <-timeout.C:
					break Loop
				case ev := <-rep.eventCh:
					if ev.meta.PID != libpf.PID(cmd.Process.Pid) {
						continue
					}
					if !gotResource && attributesMatch(ev.meta.ResourceAttrs, expectedResourceAttrs) {
						t.Logf("Got expected resource for PID %d", ev.meta.PID)
						gotResource = true
					}
					if !gotLabels && labelsMatch(ev.labels, expectedThreadLabels) {
						t.Logf("Got expected thread labels for PID %d", ev.meta.PID)
						gotLabels = true
					}
					if gotResource && gotLabels {
						break Loop
					}
				}
			}
			cancel()
			wg.Wait()
			require.True(t, gotResource, "process context not received")
			require.True(t, gotLabels, "thread context labels not received")
			t.Log("Exiting test case")
		})
	}
}

// attributesMatch reports whether every key in want is present in attrs with
// the expected string value. Extra keys in attrs are ignored.
func attributesMatch(attrs attribute.Set, want map[string]string) bool {
	for k, v := range want {
		got, ok := attrs.Value(attribute.Key(k))
		if !ok || got.Type() != attribute.STRING || got.AsString() != v {
			return false
		}
	}
	return true
}

// labelsMatch reports whether labels holds exactly want, so a wrong key index
// or a truncated value fails rather than being ignored.
func labelsMatch(labels map[libpf.String]libpf.String, want map[string]string) bool {
	if len(labels) != len(want) {
		return false
	}
	for k, v := range want {
		got, ok := labels[libpf.Intern(k)]
		if !ok || got.String() != v {
			return false
		}
	}
	return true
}
