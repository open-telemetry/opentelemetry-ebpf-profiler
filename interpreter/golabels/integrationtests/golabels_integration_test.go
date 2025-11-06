//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests

import (
	"context"
	_ "embed"
	"math"
	"os"
	"os/exec"
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
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
)

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration  { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration { return 1 * time.Second }

func isRoot() bool {
	return os.Geteuid() == 0
}

func Test_Golabels(t *testing.T) {
	if !isRoot() {
		t.Skip("root privileges required")
	}

	tests := map[string]struct {
		bin []byte
	}{
		"pprof_1_23":         {bin: pprof_1_23},
		"pprof_1_24":         {bin: pprof_1_24},
		"pprof_1_24_cgo":     {bin: pprof_1_24_cgo},
		"pprof_1_24_cgo_pie": {bin: pprof_1_24_cgo_pie},
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

			enabledTracers, _ := tracertypes.Parse("")
			enabledTracers.Enable(tracertypes.Labels)
			enabledTracers.Enable(tracertypes.GoTracer)

			log.SetDebugLogger()
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

			traceCh := make(chan *host.Trace)
			require.NoError(t, trc.StartMapMonitors(ctx, traceCh))

			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				err := exec.CommandContext(ctx, exe.Name()).Run()
				select {
				case <-ctx.Done():
					t.Log("Test program cancelled (run complete)")
				default:
					// Normal exit. We failed to capture frames.
					require.NoError(t, err)
					cancel()
					// For now, let's also panic. This allows to see
					// the backtrace what the tracer is doing.
					panic("failed to capture golabel frames")
				}
			}()

			ok := false
			for trace := range traceCh {
				if trace == nil {
					continue
				}
				if len(trace.CustomLabels) > 0 {
					hits := 0
					for ks, vs := range trace.CustomLabels {
						k := ks.String()
						v := vs.String()
						if strings.HasPrefix(k, "l1") {
							require.Len(t, v, 22)
							require.True(t, strings.HasPrefix(v, "label1"))
							hits |= (1 << 0)
						} else if strings.HasPrefix(k, "l2") {
							require.Len(t, v, 30)
							require.True(t, strings.HasPrefix(v, "label2"))
							hits |= (1 << 1)
						} else if strings.HasPrefix(k, "l3") {
							require.Len(t, v, 47)
							require.True(t, strings.HasPrefix(v, "label3"))
							hits |= (1 << 2)
						}
					}
					if hits == (1<<0 | 1<<1 | 1<<2) {
						t.Log("All labels received")
						ok = true
						cancel()
						break
					}
				}
			}
			t.Log("Exiting test case")
			require.True(t, ok, "golabels not received")
			wg.Wait()
		})
	}
}
