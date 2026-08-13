//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer_test

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/probes/crash"
	"go.opentelemetry.io/ebpf-profiler/probes/oom"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// newProbeTracer builds a tracer with the kprobe unwinder chain loaded, which is
// the precondition for Enable to attach custom probes.
func newProbeTracer(t *testing.T) *tracer.Tracer {
	t.Helper()
	tr, err := tracer.NewTracer(t.Context(), &tracer.Config{
		Intervals:              &mockIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		SamplesPerSecond:       20,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		// A non-zero OffCPUThreshold loads the kprobe unwinder chain that Enable
		// requires to attach custom probes.
		OffCPUThreshold: uint32(math.MaxUint32 / 100),
		VerboseMode:     true,
		// The test host runs inside a PID namespace; the tracer's system-analysis
		// self-probe only resolves the current PID when translation is enabled.
		// This also exercises PID-namespace var propagation into custom probes.
		PIDNamespaceTranslation: true,
	})
	require.NoError(t, err)
	return tr
}

// TestCrashProbeLoads verifies the do_coredump crash probe passes the verifier
// and attaches as a kprobe.
func TestCrashProbeLoads(t *testing.T) {
	tr := newProbeTracer(t)
	defer tr.Close()

	p, err := crash.New(crash.Config{})
	require.NoError(t, err)
	require.NoError(t, tr.Enable(t.Context(), p))
}

// TestOOMProbeLoads verifies the oom_kill_process probe passes the verifier and
// attaches as a kprobe.
func TestOOMProbeLoads(t *testing.T) {
	tr := newProbeTracer(t)
	defer tr.Close()

	p, err := oom.New(oom.Config{})
	require.NoError(t, err)
	require.NoError(t, tr.Enable(t.Context(), p))
}

// TestCrashAndOOMProbesCoexist verifies both probes can be enabled on the same
// tracer, since each allocates its own origin ID and isolated RODATA map.
func TestCrashAndOOMProbesCoexist(t *testing.T) {
	tr := newProbeTracer(t)
	defer tr.Close()

	cp, err := crash.New(crash.Config{})
	require.NoError(t, err)
	require.NoError(t, tr.Enable(t.Context(), cp))

	op, err := oom.New(oom.Config{})
	require.NoError(t, err)
	require.NoError(t, tr.Enable(t.Context(), op))
}
