//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer_test

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/probes/offcpu"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

type probeProvider interface {
	Probe() tracer.Probe
}

func TestOffCPUModesEmitDuration(t *testing.T) {
	for _, mode := range []offcpu.Mode{offcpu.ModeTracepoint, offcpu.ModeTracepointKprobe} {
		t.Run(string(mode), func(t *testing.T) {
			testOffCPUModeEmitsDuration(t, mode)
		})
	}
}

func testOffCPUModeEmitsDuration(t *testing.T, mode offcpu.Mode) {
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

	factory := offcpu.NewFactory()
	ext, err := factory.Create(ctx, extension.Settings{
		ID: component.NewID(factory.Type()),
	}, &offcpu.Config{Threshold: 1, Mode: mode})
	require.NoError(t, err)
	provider, ok := ext.(probeProvider)
	require.True(t, ok)
	require.NoError(t, tr.Enable(ctx, provider.Probe()))

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
