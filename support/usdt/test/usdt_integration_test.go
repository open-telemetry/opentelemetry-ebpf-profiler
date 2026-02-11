//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package test

import (
	"context"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	cebpf "github.com/cilium/ebpf"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

type mockReporter struct{}

func (mockReporter) ExecutableKnown(_ libpf.FileID) bool { return true }

// testSetup encapsulates all the common test setup
type testSetup struct {
	t           *testing.T
	testBinary  string
	testProbes  map[string]pfelf.USDTProbe
	probeList   []pfelf.USDTProbe
	tracer      *tracer.Tracer
	ebpfHandler interpreter.EbpfHandler
	resultsMap  *cebpf.Map
	ctx         context.Context
	cancelFunc  context.CancelFunc
}

// setupTest performs all common initialization for USDT integration tests
func setupTest(t *testing.T) *testSetup {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges to load eBPF programs")
	}

	if !util.HasBpfGetAttachCookie() {
		t.Skip("This test requires kernel support for bpf_get_attach_cookie")
	}

	// Get the test binary path
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatalf("failed to get test binary path: %v", err)
	}
	t.Logf("Test binary path: %s, PID: %d", testBinary, os.Getpid())

	// Parse USDT probes from the test binary
	ef, err := pfelf.Open(testBinary)
	if err != nil {
		t.Fatalf("failed to open test binary: %v", err)
	}
	defer ef.Close()

	if err := ef.LoadSections(); err != nil {
		t.Fatalf("failed to load sections: %v", err)
	}

	allProbes, err := ef.ParseUSDTProbes()
	if err != nil {
		t.Fatalf("failed to parse USDT probes: %v", err)
	}

	if len(allProbes) == 0 {
		t.Skip("no USDT probes found in binary")
	}

	// Filter for testprov probes
	testProbes := make(map[string]pfelf.USDTProbe)
	for _, probe := range allProbes {
		if probe.Provider == "testprov" {
			testProbes[probe.Name] = probe
			t.Logf("Found test probe: %s with args: %s at location=0x%x base=0x%x",
				probe.Name, probe.Arguments, probe.Location, probe.Base)
		}
	}

	if len(testProbes) == 0 {
		t.Skip("no testprov USDT probes found in test binary")
	}

	// Build list of probes in order
	probeList := []pfelf.USDTProbe{
		testProbes["simple_probe"],
		testProbes["memory_probe"],
		testProbes["const_probe"],
		testProbes["mixed_probe"],
		testProbes["int32_args"],
		testProbes["int64_args"],
		testProbes["mixed_refs"],
		testProbes["uint8_args"],
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize the full tracer with debug output enabled
	enabledTracers, _ := tracertypes.Parse("")
	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		IncludeTracers:         enabledTracers,
		FilterErrorFrames:      false,
		SamplesPerSecond:       20,
		MapScaleFactor:         0,
		KernelVersionCheck:     true,
		BPFVerifierLogLevel:    0,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		OffCPUThreshold:        1 * math.MaxUint32,
		VerboseMode:            true, // Enable debug output
	})
	require.NoError(t, err)

	// Get the eBPF maps and handler
	maps := tr.GetEbpfMaps()
	resultsMap := maps["usdt_test_results"]
	if resultsMap == nil {
		tr.Close()
		cancel()
		t.Fatal("usdt_test_results map not found")
	}

	ebpfHandler := tr.GetEbpfHandler()

	return &testSetup{
		t:           t,
		testBinary:  testBinary,
		testProbes:  testProbes,
		probeList:   probeList,
		tracer:      tr,
		ebpfHandler: ebpfHandler,
		resultsMap:  resultsMap,
		ctx:         ctx,
		cancelFunc:  cancel,
	}
}

// cleanup releases all test resources
func (s *testSetup) cleanup() {
	if s.tracer != nil {
		s.tracer.Close()
	}
	if s.cancelFunc != nil {
		s.cancelFunc()
	}
}

// triggerProbes calls the test probes multiple times
func (s *testSetup) triggerProbes() {
	s.t.Log("Triggering USDT probes...")
	s.t.Logf("About to call CallTestProbes() - if probes are instrumented, they should fire")

	// Call probes multiple times to ensure they fire
	for i := 0; i < 10; i++ {
		CallTestProbes()
		time.Sleep(10 * time.Millisecond)
	}
	s.t.Logf("CallTestProbes() completed 10 iterations")
}

// verifyResults checks that the probes fired and returned correct values
func (s *testSetup) verifyResults() {
	s.t.Log("Checking results...")
	passCount := 0
	failCount := 0

	for i, probe := range s.probeList {
		var value uint64
		// Probe IDs are hardcoded in usdt_test.ebpf.c as 1-8
		probeID := uint32(i + 1)

		err := s.resultsMap.Lookup(&probeID, &value)
		if err != nil {
			s.t.Logf("⚠️  Probe %s (probe_id=%d): no result (probe may not have fired)", probe.Name, probeID)
			continue
		}

		if value == 1 {
			s.t.Logf("✓ Probe %s: SUCCESS - arguments matched expected values", probe.Name)
			passCount++
		} else {
			s.t.Errorf("✗ Probe %s: FAILED - arguments did not match", probe.Name)
			failCount++
		}
	}

	s.t.Logf("\nResults: %d passed, %d failed, %d total", passCount, failCount, len(s.probeList))

	if failCount > 0 {
		s.t.Fatalf("%d probe(s) failed validation", failCount)
	}

	if passCount == 0 {
		s.t.Fatal("No probes successfully fired - check if probes are being triggered")
	}
}

// TestUSDTProbeWithEBPFSingle tests USDT probes using individual eBPF programs.
// Each probe gets its own dedicated eBPF program that extracts and validates arguments.
func TestUSDTProbeWithEBPFSingle(t *testing.T) {
	setup := setupTest(t)
	defer setup.cleanup()

	// Individual program names for each probe
	progNames := []string{
		"simple_probe",
		"memory_probe",
		"const_probe",
		"mixed_probe",
		"int32_args",
		"int64_args",
		"mixed_refs",
		"uint8_args",
	}

	// Attach USDT probes with individual programs
	// AttachUSDTProbes will automatically populate spec maps and merge spec IDs with cookies
	lc, err := setup.ebpfHandler.AttachUSDTProbes(
		libpf.PID(os.Getpid()),
		setup.testBinary,
		"", // no multi-prog (use individual programs)
		setup.probeList,
		nil, // no user cookies, just spec IDs
		progNames,
	)
	if err != nil {
		t.Fatalf("failed to attach USDT probes: %v", err)
	}
	defer lc.Unload()

	// Log what was attached
	for i, probe := range setup.probeList {
		t.Logf("Attached eBPF program %s to %s at 0x%x",
			progNames[i], probe.Name, probe.Location)
	}

	setup.triggerProbes()
	setup.verifyResults()
}

// TestUSDTProbeWithEBPFMulti tests USDT probes using multi-probe attachment with cookies.
// This mimics how CUDA probes work: one multi-probe program that dispatches based on cookie.
func TestUSDTProbeWithEBPFMulti(t *testing.T) {
	if !util.HasMultiUprobeSupport() {
		t.Skip("This test requires kernel support for uprobe multi-attach")
	}

	setup := setupTest(t)
	defer setup.cleanup()

	// Use probe IDs (1-8) as cookies for dispatch in the multi-probe program
	cookies := []uint64{1, 2, 3, 4, 5, 6, 7, 8}

	// Attach USDT probes with multi-probe program
	// This uses cookie-based dispatch like the CUDA interpreter
	lc, err := setup.ebpfHandler.AttachUSDTProbes(
		libpf.PID(os.Getpid()),
		setup.testBinary,
		"usdt_test_multi", // multi-probe program name
		setup.probeList,
		cookies, // cookies for dispatch (probe IDs 1-8)
		nil,     // no individual programs
	)
	if err != nil {
		t.Fatalf("failed to attach USDT probes: %v", err)
	}
	defer lc.Unload()

	// Log what was attached
	t.Logf("Attached multi-probe program usdt_test_multi to %d probes", len(setup.probeList))

	setup.triggerProbes()
	setup.verifyResults()
}
