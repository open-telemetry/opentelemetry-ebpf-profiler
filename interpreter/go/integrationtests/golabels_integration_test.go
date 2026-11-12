//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests

import (
	"context"
	_ "embed"
	"log/slog"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

var (
	//go:embed pprof_1_23
	pprof_1_23 []byte

	//go:embed pprof_1_24
	pprof_1_24 []byte

	//go:embed pprof_1_24_cgo
	pprof_1_24_cgo []byte

	//go:embed pprof_1_24_cgo_pie
	pprof_1_24_cgo_pie []byte

	//go:embed pprof_stable
	pprof_stable []byte

	//go:embed pprof_stable_cgo
	pprof_stable_cgo []byte

	//go:embed pprof_stable_cgo_pie
	pprof_stable_cgo_pie []byte

	allCPUs = []int{}
)

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

func isRoot() bool {
	return os.Geteuid() == 0
}

// golabelHooks accumulates the custom labels seen on sampling traces, and
// signals once all expected labels have been observed.
type golabelHooks struct {
	pm.StubTraceHandlerHooks
	t    *testing.T
	mu   sync.Mutex
	hits int
	seen chan libpf.Void
}

func (h *golabelHooks) PostHandleTrace(_ *pm.TraceContext, trace *libpf.Trace) {
	// assert is safe off the test goroutine; require is not.
	localHits := 0
	for ks, vs := range trace.CustomLabels {
		k := ks.String()
		v := vs.String()
		switch {
		case strings.HasPrefix(k, "l1"):
			assert.Len(h.t, v, 22)
			assert.True(h.t, strings.HasPrefix(v, "label1"))
			localHits |= (1 << 0)
		case strings.HasPrefix(k, "l2"):
			assert.Len(h.t, v, 30)
			assert.True(h.t, strings.HasPrefix(v, "label2"))
			localHits |= (1 << 1)
		case strings.HasPrefix(k, "l3"):
			assert.Len(h.t, v, 47)
			assert.True(h.t, strings.HasPrefix(v, "label3"))
			localHits |= (1 << 2)
		}
	}
	h.mu.Lock()
	h.hits |= localHits
	complete := h.hits == (1<<0 | 1<<1 | 1<<2)
	h.mu.Unlock()
	if complete {
		select {
		case h.seen <- libpf.Void{}:
		default:
		}
	}
}

func Test_Golabels(t *testing.T) {
	if !isRoot() {
		t.Skip("root privileges required")
	}

	tests := map[string]struct {
		bin []byte
	}{
		"pprof_1_23":           {bin: pprof_1_23},
		"pprof_1_24":           {bin: pprof_1_24},
		"pprof_1_24_cgo":       {bin: pprof_1_24_cgo},
		"pprof_1_24_cgo_pie":   {bin: pprof_1_24_cgo_pie},
		"pprof_stable":         {bin: pprof_stable},
		"pprof_stable_cgo":     {bin: pprof_stable_cgo},
		"pprof_stable_cgo_pie": {bin: pprof_stable_cgo_pie},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			exe, err := os.CreateTemp(t.TempDir(), name)
			require.NoError(t, err)
			defer os.Remove(exe.Name())

			_, err = exe.Write(tc.bin)
			require.NoError(t, err)
			require.NoError(t, exe.Close())
			require.NoError(t, os.Chmod(exe.Name(), 0o755))

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			debug.SetTraceback("all")
			metrics.Start(noop.Meter{})

			log.SetLevel(slog.LevelDebug)
			// The hooks run off the test goroutine and collect the custom
			// labels of received traces.
			hooks := &golabelHooks{
				t:    t,
				seen: make(chan libpf.Void, 1),
			}
			trc, err := tracer.NewTracer(ctx, &tracer.Config{
				Intervals:              &mockIntervals{},
				InterpretersConfig:     interpreterconfig.AllInterpreters(),
				SamplesPerSecond:       20,
				ProbabilisticInterval:  100,
				ProbabilisticThreshold: 100,
				VerboseMode:            true,
				SamplingTraceHooks:     hooks,
			})
			require.NoError(t, err)
			defer trc.Close()

			trc.StartPIDEventProcessor(ctx)
			require.NoError(t, trc.AttachTracer(allCPUs))

			t.Log("Attached tracer program")
			require.NoError(t, trc.EnableProfiling())
			require.NoError(t, trc.AttachSchedMonitor())

			require.NoError(t, trc.StartMapMonitors(ctx))

			wg := sync.WaitGroup{}
			wg.Go(func() {
				err := exec.CommandContext(ctx, exe.Name()).Run()
				select {
				case <-ctx.Done():
					t.Log("Test program canceled (run complete)")
					select {
					case <-trc.Done():
						t.Error("map monitoring ended with unrecoverable errors")
					default:
					}
				default:
					// Normal exit. We failed to capture frames.
					require.NoError(t, err)
					cancel()
					// For now, let's also panic. This allows to see
					// the backtrace what the tracer is doing.
					panic("failed to capture golabel frames")
				}
			})

			var ok bool
			select {
			case <-hooks.seen:
				ok = true
				cancel()
			case <-time.After(30 * time.Second):
				hooks.mu.Lock()
				received := hooks.hits
				hooks.mu.Unlock()
				t.Logf("received label hits: %b", received)
			}
			t.Log("Exiting test case")
			require.True(t, ok, "golabels not received")
			wg.Wait()
		})
	}
}
