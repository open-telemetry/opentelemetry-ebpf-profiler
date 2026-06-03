//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtest

import (
	"context"
	"math"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

// metricValue sums the per-CPU counters for metricID from the BPF metrics
// map exposed by the tracer.
func metricValue(t *testing.T, tr *tracer.Tracer, metricID metrics.MetricID) uint64 {
	t.Helper()
	m, ok := tr.GetEbpfMaps()["metrics"]
	require.True(t, ok, "metrics map not present")

	var ebpfID uint32
	found := false
	for id, mappedID := range support.MetricsTranslation {
		if mappedID == metricID {
			ebpfID = uint32(id)
			found = true
			break
		}
	}
	require.True(t, found, "metricID %d not in MetricsTranslation", metricID)

	var perCPU []uint64
	require.NoError(t, m.Lookup(unsafe.Pointer(&ebpfID), &perCPU))
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total
}

// TestRtldDlopenUprobe verifies that the rtld interpreter attaches the dlopen
// uprobe to this process's libc and that the IDDlopenUprobeHits metric
// increments when the process subsequently calls dlopen().
func TestRtldDlopenUprobe(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root privileges required")
	}

	// WithCancel rather than WithTimeout: under QEMU emulation, eBPF program
	// load + verification can take 30+ seconds. require.Eventually below
	// bounds the per-test time.
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		IncludeTracers:         tracertypes.IncludedTracers(0),
		FilterErrorFrames:      false,
		SamplesPerSecond:       20,
		MapScaleFactor:         0,
		KernelVersionCheck:     true,
		BPFVerifierLogLevel:    0,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		OffCPUThreshold:        1 * math.MaxUint32,
		VerboseMode:            true,
	})
	require.NoError(t, err)
	defer tr.Close()

	traceCh := make(chan *libpf.EbpfTrace, 16)
	require.NoError(t, tr.StartMapMonitors(ctx, traceCh))
	tr.StartPIDEventProcessor(ctx)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-traceCh:
			}
		}
	}()

	// Drive interpreter loader discovery for this PID. The tracer's main
	// loop walks /proc/<pid>/maps as PIDs surface via on-CPU sampling, but
	// we have no on-CPU samples yet; trigger discovery directly so the
	// rtld loader installs the dlopen uprobe immediately.
	tr.ForceProcessPID(libpf.PID(os.Getpid()))

	candidates := []string{
		"/lib/x86_64-linux-gnu/libm.so.6",
		"/lib/aarch64-linux-gnu/libm.so.6",
		"/lib64/libm.so.6",
		"libm.so.6",
	}
	dlopenOnce := func() bool {
		for _, lib := range candidates {
			if dlopenLib(lib) == nil {
				return true
			}
		}
		return false
	}

	require.Eventually(t, func() bool {
		before := metricValue(t, tr, metrics.IDDlopenUprobeHits)
		if !dlopenOnce() {
			t.Fatal("could not dlopen any libm candidate")
		}
		after := metricValue(t, tr, metrics.IDDlopenUprobeHits)
		t.Logf("DlopenUprobeHits before=%d after=%d", before, after)
		return after > before
	}, 10*time.Second, 100*time.Millisecond,
		"dlopen uprobe never fired against libm")
}
