//go:build integration

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests

import (
	"context"
	"math"
	"math/rand"
	"os"
	"runtime/debug"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration  { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration { return 1 * time.Second }

type mockReporter struct{}

func (mockReporter) ExecutableKnown(_ libpf.FileID) bool                   { return true }
func (mockReporter) ExecutableMetadata(_ *reporter.ExecutableMetadataArgs) {}

func isRoot() bool {
	return os.Geteuid() == 0
}

//nolint:gosec
func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

func setPprofLabels(t *testing.T, ctx context.Context, cookie string, busyFunc func()) {
	t.Helper()
	labels := pprof.Labels(
		"l1"+cookie, "label1"+randomString(16),
		"l2"+cookie, "label2"+randomString(24),
		"l3"+cookie, "label3"+randomString(48))
	lastUpdate := time.Now()
	pprof.Do(context.TODO(), labels, func(context.Context) {
		for time.Since(lastUpdate) < 10*time.Second {
			// CPU go burr on purpose.
			busyFunc()
			if ctx.Err() != nil {
				return
			}
		}
	})
}

func Test_Golabels(t *testing.T) {
	if !isRoot() {
		t.Skip("root privileges required")
	}

	buildInfo, ok := debug.ReadBuildInfo()
	if !ok {
		t.Fatalf("Failed to get build info")
	}

	withCGO := false
	for _, setting := range buildInfo.Settings {
		if setting.Key == "CGO_ENABLED" {
			withCGO = true
		}
	}
	t.Logf("CGo is enabled: %t", withCGO)

	cookie := buildInfo.GoVersion

	t.Run(cookie, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		enabledTracers, _ := tracertypes.Parse("")
		enabledTracers.Enable(tracertypes.Labels)
		enabledTracers.Enable(tracertypes.GoTracer)

		trc, err := tracer.NewTracer(ctx, &tracer.Config{
			Reporter:               &mockReporter{},
			Intervals:              &mockIntervals{},
			IncludeTracers:         enabledTracers,
			SamplesPerSecond:       20,
			ProbabilisticInterval:  100,
			ProbabilisticThreshold: 100,
			OffCPUThreshold:        uint32(math.MaxUint32 / 100),
			VerboseMode:            true,
		})
		require.NoError(t, err)

		trc.StartPIDEventProcessor(ctx)

		err = trc.AttachTracer()
		require.NoError(t, err)

		t.Log("Attached tracer program")

		err = trc.EnableProfiling()
		require.NoError(t, err)

		err = trc.AttachSchedMonitor()
		require.NoError(t, err)

		traceCh := make(chan *host.Trace)

		err = trc.StartMapMonitors(ctx, traceCh)
		require.NoError(t, err)

		go setPprofLabels(t, ctx, cookie, busyFunc)

		for trace := range traceCh {
			if trace == nil {
				continue
			}
			if len(trace.CustomLabels) > 0 {
				hits := 0
				for k, v := range trace.CustomLabels {
					switch k {
					case "l1" + cookie:
						require.Len(t, v, 22)
						require.True(t, strings.HasPrefix(v, "label1"))
						hits |= (1 << 0)
					case "l2" + cookie:
						require.Len(t, v, 30)
						require.True(t, strings.HasPrefix(v, "label2"))
						hits |= (1 << 1)
					case "l3" + cookie:
						require.Len(t, v, 47)
						require.True(t, strings.HasPrefix(v, "label3"))
						hits |= (1 << 2)
					}
				}
				if hits == (1<<0 | 1<<1 | 1<<2) {
					cancel()
					break
				}
			}
		}
	})
}
