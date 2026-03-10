//go:build linux

package cudaverify

import (
	"bytes"
	"context"
	"flag"
	"math"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var soPath = flag.String("so-path", "/libparcagpucupti.so", "path to libparcagpucupti.so")

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

type mockReporter struct{}

func (mockReporter) ExecutableKnown(_ libpf.FileID) bool { return true }

// discardTraceReporter is a TraceReporter that silently discards all traces.
type discardTraceReporter struct{}

func (discardTraceReporter) ReportTraceEvent(_ *libpf.Trace, _ *samples.TraceEventMeta) error {
	return nil
}

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
		"", // no multi-prog
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
			err := ebpfHandler.UpdateProgArray("cuda_progs", 0, "cuda_activity_batch_tail")
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

// runEndToEnd exercises the full process-manager driven GPU probe attachment flow:
//
//  1. Start the full tracer pipeline (PID event processor, map monitors, profiling).
//  2. ForceProcessPID to trigger initial process sync — this causes the tracer to
//     read our /proc/self/maps, discover libc, and attach the dlopen uprobe via rtld.
//  3. Wait until the dlopen uprobe is confirmed attached (metric increments).
//  4. dlopen libparcagpu — the dlopen uprobe fires, triggering a re-sync that
//     discovers libparcagpu and automatically attaches the GPU USDT probes.
//  5. Verify GPU interpreter instance is attached, then simulate kernel launches
//     and check that timing events arrive on the perf buffer.
func runEndToEnd(t *testing.T, multiProbe bool) {
	t.Helper()

	if !multiProbe {
		noMulti := false
		util.SetTestOnlyMultiUprobeSupport(&noMulti)
		defer util.SetTestOnlyMultiUprobeSupport(nil)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	enabledTracers, _ := tracertypes.Parse("")
	enabledTracers.Enable(tracertypes.CUDATracer)

	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		TraceReporter:          discardTraceReporter{},
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
		VerboseMode:            true,
	})
	require.NoError(t, err, "failed to create tracer")
	defer tr.Close()

	// Start the full pipeline: PID event processor, profiling, map monitors.
	tr.StartPIDEventProcessor(ctx)
	require.NoError(t, tr.AttachTracer(), "AttachTracer failed")
	require.NoError(t, tr.EnableProfiling(), "EnableProfiling failed")
	require.NoError(t, tr.AttachSchedMonitor(), "AttachSchedMonitor failed")

	ebpfTraceCh := make(chan *libpf.EbpfTrace)
	require.NoError(t, tr.StartMapMonitors(ctx, ebpfTraceCh), "StartMapMonitors failed")

	// Consume eBPF traces to prevent blocking the pipeline.
	go func() {
		for {
			select {
			case trace := <-ebpfTraceCh:
				if trace != nil {
					tr.HandleTrace(trace)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// Trigger initial process sync for our PID so the tracer discovers our
	// mappings and attaches the dlopen uprobe to libc.
	pid := libpf.PID(uint32(os.Getpid()))
	tr.ForceProcessPID(pid)

	// Wait until the process manager has processed our PID and attached
	// interpreter instances (the rtld instance attaches the dlopen uprobe
	// to libc as a side effect).
	require.Eventually(t, func() bool {
		instances := tr.GetInterpretersForPID(pid)
		if len(instances) > 0 {
			t.Logf("process synced: %d interpreter(s) attached", len(instances))
			return true
		}
		t.Log("waiting for initial process sync...")
		tr.ForceProcessPID(pid)
		return false
	}, 15*time.Second, 200*time.Millisecond, "process manager never synced our PID")

	// Set up perf reader on the cuda_timing_events map BEFORE the dlopen so we
	// don't miss any events.
	timingMap := tr.GetEbpfMaps()["cuda_timing_events"]
	require.NotNil(t, timingMap, "cuda_timing_events map not found")

	reader, err := perf.NewReader(timingMap, 1024*1024)
	require.NoError(t, err, "perf.NewReader failed")
	defer reader.Close()

	// dlopen libparcagpu — this fires the dlopen uprobe, which causes a PID
	// re-sync. The process manager will discover the newly mapped .so, the GPU
	// loader will find its USDT probes, and Attach will hook them up.
	rc := cInitParcaGPU(*soPath)
	require.Equal(t, 0, rc, "init_parcagpu (dlopen) failed")
	defer cCleanupParcaGPU()

	// Speed up the re-sync after dlopen.
	tr.ForceProcessPID(pid)

	// Wait until the GPU interpreter instance appears, confirming the USDT
	// probes were attached by the process manager.
	require.Eventually(t, func() bool {
		instances := tr.GetInterpretersForPID(pid)
		for _, inst := range instances {
			if _, ok := inst.(*gpu.Instance); ok {
				t.Log("GPU interpreter instance attached")
				return true
			}
		}
		t.Logf("waiting for GPU interpreter instance (%d interpreters so far)...", len(instances))
		tr.ForceProcessPID(pid)
		return false
	}, 15*time.Second, 200*time.Millisecond, "GPU interpreter never attached after dlopen")

	// Simulate kernel launches and wait for timing events.  Retry the
	// simulation several times — on slow CI the uprobes may not be fully
	// active in the kernel immediately after the interpreter is detected.
	var events []gpu.CuptiTimingEvent
	var rec perf.Record

	const (
		maxAttempts  = 3
		pollTimeout  = 5 * time.Second
		pollInterval = 200 * time.Millisecond
	)

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		t.Logf("simulation attempt %d/%d", attempt, maxAttempts)

		// Simulate a kernel launch (fires cuda_correlation USDT).
		cSimulateKernelLaunch(42)

		// Simulate buffer completion (fires kernel_executed + activity_batch USDTs).
		cSimulateBufferCompletion(42, 0, 7, "testKernel")

		// Poll perf reader for timing events.
		deadline := time.After(pollTimeout)
		for {
			reader.SetDeadline(time.Now().Add(pollInterval))
			err := reader.ReadInto(&rec)
			if err != nil {
				select {
				case <-deadline:
					goto nextAttempt
				default:
					continue
				}
			}
			if rec.LostSamples != 0 || len(rec.RawSample) == 0 {
				continue
			}
			ev := (*gpu.CuptiTimingEvent)(unsafe.Pointer(&rec.RawSample[0]))
			events = append(events, *ev)
			t.Logf("Received timing event: pid=%d id=%d dev=%d stream=%d kernel=%s",
				ev.Pid, ev.Id, ev.Dev, ev.Stream,
				string(ev.KernelName[:bytes.IndexByte(ev.KernelName[:], 0)]))
		}
	nextAttempt:
		if len(events) > 0 {
			break
		}
		t.Logf("no events after attempt %d, retrying...", attempt)
	}

	require.NotEmpty(t, events, "no timing events received from cuda_timing_events perf buffer after %d attempts", maxAttempts)

	// Verify at least one event matches our simulated kernel.
	found := false
	for _, ev := range events {
		nameBytes := ev.KernelName[:]
		if idx := bytes.IndexByte(nameBytes, 0); idx >= 0 {
			nameBytes = nameBytes[:idx]
		}
		if ev.Id == 42 && ev.Dev == 0 && ev.Stream == 7 &&
			string(nameBytes) == "testKernel" {
			found = true
			break
		}
	}
	require.True(t, found,
		"expected timing event with correlation_id=42, device_id=0, stream_id=7, kernel_name=testKernel; got %+v", events)
}

// TestCUDAEndToEndSingleShot verifies that CUDA USDT probes fire correctly
// using individual per-probe attachment (kernel 5.15+).
func TestCUDAEndToEndSingleShot(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF programs")
	}
	if !util.HasBpfGetAttachCookie() {
		t.Skip("requires kernel support for bpf_get_attach_cookie (5.15+)")
	}

	runEndToEnd(t, false)
}

// TestCUDAEndToEndMultiProbe verifies that CUDA USDT probes fire correctly
// using multi-uprobe attachment with tail calls (kernel 6.6+).
func TestCUDAEndToEndMultiProbe(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("requires root to load eBPF programs")
	}
	if !util.HasBpfGetAttachCookie() {
		t.Skip("requires kernel support for bpf_get_attach_cookie (5.15+)")
	}
	if !util.HasMultiUprobeSupport() {
		t.Skip("requires kernel support for uprobe multi-attach (6.6+)")
	}

	runEndToEnd(t, true)
}
