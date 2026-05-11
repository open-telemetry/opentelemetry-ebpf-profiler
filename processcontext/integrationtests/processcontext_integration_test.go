//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests

import (
	"context"
	"log/slog"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/otel/metric/noop"
)

// expectedResource lists the resource attributes the testdata C programs
// publish via init_process_context() in processctx_lib.c.
var expectedResource = map[string]string{
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

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

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
		// "musl_exe":     {exeName: "processctx_exe_musl"},
		// "glibc_lib":    {exeName: "processctx_lib_glibc"},
		// "musl_lib":     {exeName: "processctx_lib_musl"},
		// "glibc_dlopen": {exeName: "processctx_dlopen_glibc", args: []string{filepath.Join(exeDir, "libprocessctx_glibc.so")}},
		// "musl_dlopen":  {exeName: "processctx_dlopen_musl", args: []string{filepath.Join(exeDir, "libprocessctx_musl.so")}},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			metrics.Start(noop.Meter{})

			enabledTracers, _ := tracertypes.Parse("")

			log.SetLevel(slog.LevelDebug)
			trc, err := tracer.NewTracer(ctx, &tracer.Config{
				Intervals:              &mockIntervals{},
				IncludeTracers:         enabledTracers,
				SamplesPerSecond:       20,
				ProbabilisticInterval:  100,
				ProbabilisticThreshold: 100,
				OffCPUThreshold:        uint32(math.MaxUint32 / 100),
				VerboseMode:            true,
			})
			require.NoError(t, err)
			defer trc.Close()

			trc.StartPIDEventProcessor(ctx)
			require.NoError(t, trc.AttachTracer())

			t.Log("Attached tracer program")
			require.NoError(t, trc.EnableProfiling())
			require.NoError(t, trc.AttachSchedMonitor())

			traceCh := make(chan *libpf.EbpfTrace)
			require.NoError(t, trc.StartMapMonitors(ctx, traceCh))

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
					// require.* must run on the test goroutine; mark the test
					// as failed here and cancel so the main loop unblocks and
					// reports the early child exit.
					t.Errorf("test program exited unexpectedly: %v", err)
					cancel()
				}
			}()

			timeout := time.NewTimer(10 * time.Second)
			defer timeout.Stop()

			ok := false
		Loop:
			for {
				select {
				case <-timeout.C:
					break Loop
				case trace := <-traceCh:
					if trace == nil || trace.PID != libpf.PID(cmd.Process.Pid) {
						continue
					}
					if trace.Resource == nil {
						continue
					}
					if !resourceMatches(trace.Resource, expectedResource) {
						continue
					}
					t.Logf("Got expected resource for PID %d", trace.PID)
					ok = true
					break Loop
				}
			}
			cancel()
			wg.Wait()
			require.True(t, ok, "process context not received")
			t.Log("Exiting test case")
		})
	}
}

// resourceMatches reports whether every key in want is present in r with the
// expected value (other keys in r are ignored). Returns false on the first
// missing key or value mismatch.
func resourceMatches(r *pcommon.Resource, want map[string]string) bool {
	attrs := r.Attributes()
	for k, v := range want {
		got, ok := attrs.Get(k)
		if !ok || got.Type() != pcommon.ValueTypeStr || got.Str() != v {
			return false
		}
	}
	return true
}
