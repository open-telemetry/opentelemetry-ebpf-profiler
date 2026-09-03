//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package offcpu

import (
	"context"
	"math"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

func TestMain(m *testing.M) {
	metrics.Start(noop.Meter{})
	os.Exit(m.Run())
}

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return time.Second }

func TestModesEmitDuration(t *testing.T) {
	for _, mode := range []Mode{ModeTracepoint, ModeTracepointKprobe} {
		t.Run(string(mode), func(t *testing.T) {
			testModeEmitsDuration(t, mode)
		})
	}
}

func testModeEmitsDuration(t *testing.T, mode Mode) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		FilterErrorFrames:      false,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
	})
	require.NoError(t, err)
	defer tr.Close()

	traceCh := make(chan *libpf.EbpfTrace, 128)
	tr.StartPIDEventProcessor(ctx)
	require.NoError(t, tr.StartMapMonitors(ctx, traceCh))

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	tr.SynchronizeProcessForTest(libpf.PID(os.Getpid()), libpf.PID(unix.Gettid()))
	require.NoError(t, tr.Enable(ctx, &probe{threshold: math.MaxUint32, mode: mode}))

	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()

	for {
		// A direct nanosleep blocks this OS thread, guaranteeing that the
		// sched_switch tracepoint observes it switching out and back in.
		sleep := unix.NsecToTimespec((5 * time.Millisecond).Nanoseconds())
		_ = unix.Nanosleep(&sleep, nil)
		select {
		case trace := <-traceCh:
			if trace != nil && trace.Value > 0 {
				return
			}
		case <-deadline.C:
			t.Fatal("did not receive an off-CPU trace with a measured duration")
		default:
		}
	}
}
