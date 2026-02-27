//go:build linux

package cudaverify

import (
	"context"
	"flag"
	"math"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var soPath = flag.String("so-path", "/libparcagpucupti.so", "path to libparcagpucupti.so")

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration  { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration { return 1 * time.Second }

type mockReporter struct{}

func (mockReporter) ExecutableKnown(_ libpf.FileID) bool                   { return true }
func (mockReporter) ExecutableMetadata(_ *reporter.ExecutableMetadataArgs) {}

// parseProbes opens the .so and extracts the required parcagpu USDT probes.
func parseProbes(t *testing.T) []pfelf.USDTProbe {
	t.Helper()

	ef, err := pfelf.Open(*soPath)
	require.NoError(t, err, "failed to open %s", *soPath)
	defer ef.Close()

	require.NoError(t, ef.LoadSections(), "failed to load sections")

	allProbes, err := ef.ParseUSDTProbes()
	require.NoError(t, err, "failed to parse USDT probes")

	var requiredProbes []pfelf.USDTProbe
	for _, probe := range allProbes {
		if probe.Provider == "parcagpu" &&
			(probe.Name == "cuda_correlation" || probe.Name == "kernel_executed" || probe.Name == "activity_batch") {
			requiredProbes = append(requiredProbes, probe)
		}
	}
	// Need cuda_correlation + at least one of kernel_executed/activity_batch
	hasCorrelation := false
	hasKernel := false
	for _, p := range requiredProbes {
		switch p.Name {
		case "cuda_correlation":
			hasCorrelation = true
		case "kernel_executed", "activity_batch":
			hasKernel = true
		}
	}
	require.True(t, hasCorrelation, "missing cuda_correlation probe")
	require.True(t, hasKernel, "missing kernel_executed or activity_batch probe")

	for _, p := range requiredProbes {
		t.Logf("Found probe: provider=%s name=%s location=0x%x args=%s",
			p.Provider, p.Name, p.Location, p.Arguments)
	}
	return requiredProbes
}

// createTracer creates a Tracer with InstrumentCudaLaunch enabled so the CUDA
// eBPF programs (tail-call destinations) are loaded and the verifier runs.
func createTracer(t *testing.T) (*tracer.Tracer, interpreter.EbpfHandler, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	enabledTracers, _ := tracertypes.Parse("")

	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Reporter:               &mockReporter{},
		Intervals:              &mockIntervals{},
		IncludeTracers:         enabledTracers,
		FilterErrorFrames:      false,
		SamplesPerSecond:       20,
		MapScaleFactor:         0,
		KernelVersionCheck:     false,
		BPFVerifierLogLevel:    0,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		OffCPUThreshold:        1 * math.MaxUint32,
		InstrumentCudaLaunch:   true,
	})
	require.NoError(t, err, "failed to create tracer")

	ebpfHandler := tr.GetEbpfHandler()
	return tr, ebpfHandler, cancel
}

// buildCookiesAndProgNames builds the cookie and program-name slices that
// mirror interpreter/gpu/cuda.go Attach().
func buildCookiesAndProgNames(probes []pfelf.USDTProbe) ([]uint64, []string) {
	cookies := make([]uint64, len(probes))
	progNames := make([]string, len(probes))
	for i, probe := range probes {
		switch probe.Name {
		case "cuda_correlation":
			cookies[i] = 0 // CudaProgCorrelation
			progNames[i] = "cuda_correlation"
		case "kernel_executed":
			cookies[i] = 1 // CudaProgKernelExec
			progNames[i] = "cuda_kernel_exec"
		case "activity_batch":
			cookies[i] = 2 // CudaProgActivityBatch
			progNames[i] = "cuda_activity_batch"
		}
	}
	return cookies, progNames
}

// TestCUDAVerifierSingleShot verifies CUDA eBPF programs pass the BPF verifier
// using individual per-probe program attachment (works on kernel 5.15+).
// Forces single-shot mode so that AttachUSDTProbes uses per-probe attachment.
func TestCUDAVerifierSingleShot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF programs")
	}
	if !util.HasBpfGetAttachCookie() {
		t.Skip("requires kernel support for bpf_get_attach_cookie (5.15+)")
	}

	// Force single-shot mode so loadUSDTProgram does not set
	// AttachTraceUprobeMulti.
	noMulti := false
	util.SetTestOnlyMultiUprobeSupport(&noMulti)
	defer util.SetTestOnlyMultiUprobeSupport(nil)

	probes := parseProbes(t)
	tr, ebpfHandler, cancel := createTracer(t)
	defer tr.Close()
	defer cancel()

	cookies, progNames := buildCookiesAndProgNames(probes)

	lc, err := ebpfHandler.AttachUSDTProbes(
		libpf.PID(os.Getpid()),
		*soPath,
		"",     // no multi-prog
		probes,
		cookies,
		progNames,
	)
	require.NoError(t, err, "AttachUSDTProbes (single-shot) failed — BPF verifier rejected CUDA programs")
	defer lc.Unload()

	t.Log("SingleShot: all CUDA eBPF programs passed the BPF verifier")
}

// TestCUDAVerifierMultiProbe verifies CUDA eBPF programs pass the BPF verifier
// using multi-uprobe attachment with cookies (requires kernel 6.6+).
func TestCUDAVerifierMultiProbe(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF programs")
	}
	if !util.HasBpfGetAttachCookie() {
		t.Skip("requires kernel support for bpf_get_attach_cookie (5.15+)")
	}
	if !util.HasMultiUprobeSupport() {
		t.Skip("requires kernel support for uprobe multi-attach (6.6+)")
	}

	probes := parseProbes(t)
	tr, ebpfHandler, cancel := createTracer(t)
	defer tr.Close()
	defer cancel()

	cookies, progNames := buildCookiesAndProgNames(probes)

	// Populate the tail-call prog array for activity_batch (the only tail-call
	// target — correlation and kernel_exec are inlined in cuda_probe).
	for _, probe := range probes {
		if probe.Name == "activity_batch" {
			err := ebpfHandler.UpdateProgArray("cuda_progs", 0, "cuda_activity_batch")
			require.NoError(t, err, "UpdateProgArray failed for cuda_activity_batch")
			break
		}
	}

	lc, err := ebpfHandler.AttachUSDTProbes(
		libpf.PID(os.Getpid()),
		*soPath,
		"cuda_probe", // multi-probe program
		probes,
		cookies,
		progNames,
	)
	require.NoError(t, err, "AttachUSDTProbes (multi-probe) failed — BPF verifier rejected CUDA programs")
	defer lc.Unload()

	t.Log("MultiProbe: all CUDA eBPF programs passed the BPF verifier")
}
