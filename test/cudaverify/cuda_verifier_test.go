//go:build linux

package cudaverify

import (
	"bytes"
	"context"
	"flag"
	"os"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/testutils"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

var soPath = flag.String("so-path", "/libparcagpucupti.so", "path to libparcagpucupti.so")

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

	_, trc := testutils.StartTracer(ctx, t, enabledTracers, false)
	defer trc.Close()

	// Trigger initial process sync for our PID so the tracer discovers our
	// mappings and attaches the dlopen uprobe to libc.
	pid := libpf.PID(uint32(os.Getpid()))
	trc.ForceProcessPID(pid)

	// Wait until the process manager has processed our PID and attached
	// interpreter instances (the rtld instance attaches the dlopen uprobe
	// to libc as a side effect).
	require.Eventually(t, func() bool {
		instances := trc.GetInterpretersForPID(pid)
		if len(instances) > 0 {
			t.Logf("process synced: %d interpreter(s) attached", len(instances))
			return true
		}
		t.Log("waiting for initial process sync...")
		trc.ForceProcessPID(pid)
		return false
	}, 30*time.Second, 200*time.Millisecond, "process manager never synced our PID")

	// Set up perf reader on the cuda_timing_events map BEFORE the dlopen so we
	// don't miss any events.
	timingMap := trc.GetEbpfMaps()["cuda_timing_events"]
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
	trc.ForceProcessPID(pid)

	// Wait until the GPU interpreter instance appears, confirming the USDT
	// probes were attached by the process manager.
	require.Eventually(t, func() bool {
		instances := trc.GetInterpretersForPID(pid)
		for _, inst := range instances {
			if _, ok := inst.(*gpu.Instance); ok {
				t.Log("GPU interpreter instance attached")
				return true
			}
		}
		t.Logf("waiting for GPU interpreter instance (%d interpreters so far)...", len(instances))
		trc.ForceProcessPID(pid)
		return false
	}, 30*time.Second, 200*time.Millisecond, "GPU interpreter never attached after dlopen")

	// Simulate kernel launches and wait for timing events.  Retry the
	// simulation several times — on slow CI the uprobes may not be fully
	// active in the kernel immediately after the interpreter is detected.
	var events []gpu.CuptiTimingEvent
	var rec perf.Record

	const (
		maxAttempts  = 10
		pollTimeout  = 10 * time.Second
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
