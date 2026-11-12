//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer_test

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/probes/heap"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

const (
	pidNamespaceProfiler = "pidns-profiler"
	pidNamespaceTarget   = "pidns-target"
	pidNamespaceSibling  = "pidns-sibling"
)

var pidNamespaceRole = flag.String(
	"pid-namespace-translation-role", "", "run the named PID namespace translation test role")

func TestMain(m *testing.M) {
	flag.Parse()
	switch *pidNamespaceRole {
	case pidNamespaceTarget, pidNamespaceSibling:
		os.Exit(runPIDNamespaceTranslationWorkload(*pidNamespaceRole))
	case pidNamespaceProfiler:
		if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
			fmt.Fprintf(os.Stderr, "make mounts private: %v\n", err)
			os.Exit(1)
		}
		if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
			fmt.Fprintf(os.Stderr, "mount profiler procfs: %v\n", err)
			os.Exit(1)
		}
	}

	// Initialize metrics once to avoid concurrent map access between
	// metrics.Start() and metrics.AddSlice() called from lingering periodiccaller goroutines.
	metrics.Start(noop.Meter{})
	os.Exit(m.Run())
}

type mockIntervals struct{}

func (mockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (mockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (mockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (mockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

// forceContextSwitch makes sure two Go threads are running concurrently
// and that there will be a context switch between those two.
func forceContextSwitch() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	wg := &sync.WaitGroup{}
	wg.Add(1)
	go func(wg *sync.WaitGroup) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		wg.Done()
	}(wg)
	wg.Wait()
}

func attachKernelFrameProbe(t *testing.T, tr *tracer.Tracer) link.Link {
	t.Helper()
	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	err = tracer.RewriteMaps(coll, tr.GetEbpfMaps())
	require.NoError(t, err)

	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	prog, err := cebpf.NewProgram(coll.Programs["tracepoint_integration__sched_switch"])
	require.NoError(t, err)
	defer prog.Close()

	event, err := link.Tracepoint("sched", "sched_switch", prog, nil)
	require.NoError(t, err)
	return event
}

// runKernelFrameProbe triggers sched/sched_switch, which sends a selection of
// hand-crafted, predictable traces.
func runKernelFrameProbe(t *testing.T, tr *tracer.Tracer) {
	t.Helper()
	event := attachKernelFrameProbe(t, tr)
	t.Logf("probe for Kernel frames installed on sched/sched_switch")

	// Manually trigger the tracepoint on sched/sched_switch.
	forceContextSwitch()

	t.Logf("tracepoint sched_switch triggered")
	require.NoError(t, event.Close())
}

// observedTrace is the trace data captured by testTraceHooks, keyed by the
// test case ID in COMM[3].
type observedTrace struct {
	numKernelFrames int
	numUserFrames   int
	// firstUserAddress is the raw address of the first non-kernel frame.
	firstUserAddress libpf.AddressOrLineno
	contextValues    []uint64
}

// testTraceHooks records traces of the integration test probe (0xAA 0xBB
// 0xCC COMM prefix).
type testTraceHooks struct {
	pm.StubTraceHandlerHooks
	traces *sync.Map // keyed by the test case ID encoded in COMM[3]
}

func (h *testTraceHooks) PostHandleTrace(ctx *pm.TraceContext, tr *libpf.Trace) {
	comm := ctx.Comm.String()
	if len(comm) < 4 || comm[:3] != "\xAA\xBB\xCC" {
		return
	}
	observed := observedTrace{contextValues: slices.Clone(ctx.ContextValues)}
	for _, uniqueFrame := range tr.Frames {
		switch frame := uniqueFrame.Value(); frame.Type {
		case libpf.KernelFrame:
			observed.numKernelFrames++
		default:
			if observed.numUserFrames == 0 {
				observed.firstUserAddress = frame.AddressOrLineno
			}
			observed.numUserFrames++
		}
	}
	h.traces.Store(comm[3], observed)
}

// probeTrace is a TraceContext snapshot; it is only valid during the hook
// call.
type probeTrace struct {
	comm string
	pid  libpf.PID
	tid  libpf.PID
}

// forwardProbeTraces forwards probe traces to the test goroutine.
type forwardProbeTraces struct {
	pm.StubTraceHandlerHooks
	traces chan<- probeTrace
}

func (f *forwardProbeTraces) PostHandleTrace(ctx *pm.TraceContext, _ *libpf.Trace) {
	comm := ctx.Comm.String()
	if len(comm) < 4 || comm[:3] != "\xAA\xBB\xCC" {
		return
	}
	select {
	case f.traces <- probeTrace{comm: comm, pid: ctx.PID, tid: ctx.TID}:
	default:
	}
}

func TestTracerErrorPropagation(t *testing.T) {
	ctx, cancelFn := context.WithCancel(t.Context())
	defer cancelFn()

	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		FilterErrorFrames:      false,
		SamplesPerSecond:       20,
		MapScaleFactor:         0,
		KernelVersionCheck:     true,
		BPFVerifierLogLevel:    0,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,

		VerboseMode: true,
	})
	require.NoError(t, err)
	defer tr.Close()

	// tamper ebpf pid_events map type to produce invalid argument error
	badSpec := &cebpf.MapSpec{
		Name:       "pid_events",
		Type:       cebpf.Queue, // Hash type is expected instead
		KeySize:    0,
		ValueSize:  4,
		MaxEntries: 100,
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	badMap, err := cebpf.NewMap(badSpec)
	require.NoError(t, err)

	tr.GetEbpfMaps()["pid_events"] = badMap

	require.NoError(t, tr.StartMapMonitors(ctx))
	<-tr.Done()
}

func TestTracerMapMonitorsError(t *testing.T) {
	ctx, cancelFn := context.WithCancel(t.Context())
	defer cancelFn()

	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		FilterErrorFrames:      false,
		SamplesPerSecond:       20,
		MapScaleFactor:         0,
		KernelVersionCheck:     true,
		BPFVerifierLogLevel:    0,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,

		VerboseMode: true,
	})
	require.NoError(t, err)
	defer tr.Close()

	// force error by removing a required map during map monitor start up
	delete(tr.GetEbpfMaps(), "report_events")

	require.Error(t, tr.StartMapMonitors(ctx))
}

func TestTraceTransmissionAndParsing(t *testing.T) {
	ctx, cancelFn := context.WithCancel(t.Context())
	defer cancelFn()

	var traces sync.Map

	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		FilterErrorFrames:      false,
		SamplesPerSecond:       20,
		MapScaleFactor:         0,
		KernelVersionCheck:     true,
		BPFVerifierLogLevel:    0,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,

		VerboseMode: true,
		SamplingTraceHooks: &testTraceHooks{
			traces: &traces,
		},
	})
	require.NoError(t, err)
	defer tr.Close()

	require.NoError(t, tr.StartMapMonitors(ctx))

	runKernelFrameProbe(t, tr)

	// Wait up to 1 second for both probe traces to arrive.
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		_, ok1 := traces.Load(uint8(1))
		_, ok2 := traces.Load(uint8(2))
		assert.True(ct, ok1 && ok2, "probe traces not received")
	}, 1*time.Second, 10*time.Millisecond)

	tests := map[string]struct {
		// id identifies the trace to inspect (encoded in COMM[3]).
		id uint8
		// hasKernelFrames indicates if the trace should contain kernel frames.
		hasKernelFrames bool
		// contextValues are expected before the kernel-frame region in variable_data.
		contextValues []uint64
	}{
		"Single Native Frame": {
			id:            1,
			contextValues: nil,
		},
		"Single Native Frame with Kernel Frames": {
			id:              2,
			hasKernelFrames: true,
			contextValues: []uint64{
				0x123456789abcdef0,
				0x2222222222222222,
				0x3333333333333333,
			},
		},
	}

	for name, testcase := range tests {
		t.Run(name, func(t *testing.T) {
			raw, ok := traces.Load(testcase.id)
			require.Truef(t, ok, "trace ID %d not received", testcase.id)
			trace := raw.(observedTrace)
			require.Equal(t, testcase.contextValues, trace.contextValues)

			numKernelFrames := trace.numKernelFrames

			assert.False(t, !testcase.hasKernelFrames && numKernelFrames > 0,
				"unexpected kernel frames")

			// If this check fails it _could_ be a false positive, in that there is not
			// in fact anything wrong with the code being tested. We hope that the
			// kernel stack we capture has at least two frames, but it is possible that
			// it does not. If this happens frequently we should consider if there is a
			// different approach to checking this property without the possibility of
			// false positives.
			assert.Falsef(t, testcase.hasKernelFrames && numKernelFrames < 2,
				"expected at least 2 kernel frames, but got %d", numKernelFrames)

			// The probe pushes a single native frame with address 21.
			t.Logf("Received %d user frames and %d kernel frames",
				trace.numUserFrames, numKernelFrames)
			assert.Equal(t, 1, trace.numUserFrames)
			assert.Equal(t, libpf.AddressOrLineno(21), trace.firstUserAddress)
		})
	}
}

func TestAllTracers(t *testing.T) {
	testcases := []struct {
		name string
		mode tracer.PIDNamespaceTranslationMode
	}{
		{name: "host PIDs", mode: tracer.PIDNamespaceTranslationModeNone},
		{name: "namespace PIDs", mode: tracer.PIDNamespaceTranslationModeAuto},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			tr, err := tracer.NewTracer(t.Context(), &tracer.Config{
				Intervals:              &mockIntervals{},
				InterpretersConfig:     interpreterconfig.AllInterpreters(),
				SamplesPerSecond:       20,
				ProbabilisticInterval:  100,
				ProbabilisticThreshold: 100,

				VerboseMode:                 true,
				PIDNamespaceTranslationMode: tc.mode,
			})
			require.NoError(t, err)
			defer tr.Close()

			heapProbe, err := heap.New(heap.Config{})
			require.NoError(t, err)
			require.NoError(t, tr.Enable(t.Context(), heapProbe))
			defer func() {
				require.NoError(t, heapProbe.Unload())
			}()
		})
	}
}

func TestPIDNamespaceTranslationRecursive(t *testing.T) {
	if *pidNamespaceRole != pidNamespaceProfiler {
		sibling := newPIDNamespaceCommand("-pid-namespace-translation-role=" + pidNamespaceSibling)
		require.NoError(t, sibling.Start())
		t.Cleanup(func() {
			_ = sibling.Process.Kill()
			_ = sibling.Wait()
		})

		profiler := newPIDNamespaceCommand(
			"-test.run=^TestPIDNamespaceTranslationRecursive$",
			"-pid-namespace-translation-role="+pidNamespaceProfiler,
		)
		profiler.SysProcAttr.Cloneflags |= syscall.CLONE_NEWNS
		output, err := profiler.CombinedOutput()
		require.NoErrorf(t, err, "profiler subprocess failed: %s", output)
		return
	}
	require.Equal(t, 1, os.Getpid(), "profiler must run as PID 1 in its namespace")
	selfPIDNamespace, err := os.Readlink("/proc/self/ns/pid")
	require.NoError(t, err)
	procPIDNamespace, err := os.Readlink("/proc/1/ns/pid")
	require.NoError(t, err)
	require.Equal(t, selfPIDNamespace, procPIDNamespace, "procfs must represent the profiler namespace")

	_, btfErr := os.Stat("/sys/kernel/btf/vmlinux")
	// Forward probe traces (0xAA 0xBB 0xCC COMM prefix) to the test goroutine.
	traceCh := make(chan probeTrace, 1024)

	tr, err := tracer.NewTracer(t.Context(), &tracer.Config{
		Intervals:                   &mockIntervals{},
		InterpretersConfig:          interpreterconfig.AllInterpreters(),
		SamplesPerSecond:            20,
		ProbabilisticInterval:       100,
		ProbabilisticThreshold:      100,
		PIDNamespaceTranslationMode: tracer.PIDNamespaceTranslationModeRecursive,
		SamplingTraceHooks:          &forwardProbeTraces{traces: traceCh},
	})
	if os.IsNotExist(btfErr) {
		require.ErrorContains(t, err, "recursive PID namespace translation requires readable kernel BTF")
		return
	}
	require.NoError(t, btfErr)
	require.NoError(t, err)
	defer tr.Close()

	require.NoError(t, tr.StartMapMonitors(t.Context()))

	event := attachKernelFrameProbe(t, tr)
	defer event.Close()

	cmd := newPIDNamespaceCommand("-pid-namespace-translation-role=" + pidNamespaceTarget)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	targetPID := libpf.PID(cmd.Process.Pid)
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			t.Fatalf("no trace received for descendant namespace PID %d", targetPID)
		case <-tr.Done():
			t.Fatal("tracer encountered an unrecoverable error")
		case pt := <-traceCh:
			if pt.comm[4:] == pidNamespaceSibling[4:] {
				t.Fatal("received trace from sibling PID namespace")
			}
			if pt.comm[4:] != pidNamespaceTarget[4:] ||
				pt.pid != targetPID || pt.tid == targetPID {
				continue
			}
			_, err := os.Stat(fmt.Sprintf("/proc/%d/task/%d", pt.pid, pt.tid))
			require.NoError(t, err, "translated TID does not belong to the target process")
			return
		}
	}
}

func newPIDNamespaceCommand(args ...string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	return cmd
}

func runPIDNamespaceTranslationWorkload(comm string) int {
	if os.Getpid() != 1 {
		fmt.Fprintf(os.Stderr, "PID namespace child has PID %d, want 1\n", os.Getpid())
		return 1
	}

	runtime.GOMAXPROCS(2)
	duration := 15 * time.Second
	deadline := time.Now().Add(duration)
	errs := make(chan error, 2)
	run := func() {
		runtime.LockOSThread()
		if err := os.WriteFile("/proc/thread-self/comm", []byte(comm), 0o644); err != nil {
			errs <- err
			return
		}
		for time.Now().Before(deadline) {
			runtime.Gosched()
		}
		errs <- nil
	}
	go run()
	go run()
	for range 2 {
		if err := <-errs; err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}
	return 0
}

// BenchmarkNewTracer measures the cost of the whole tracer startup path,
// which is dominated by loading eBPF maps and programs into the kernel.
//
// Run with:
//
//	sudo go test -tags integration -run='^$' -bench=BenchmarkNewTracer \
//	    -benchtime=5x -count=10 ./tracer/
func BenchmarkNewTracer(b *testing.B) {
	// Keep the benchmark output parseable by benchstat.
	log.SetLevel(slog.LevelError)
	b.Cleanup(func() { log.SetLevel(slog.LevelInfo) })

	ctx := b.Context()

	for b.Loop() {
		tr, err := tracer.NewTracer(ctx, &tracer.Config{
			Intervals:              &mockIntervals{},
			InterpretersConfig:     interpreterconfig.AllInterpreters(),
			FilterErrorFrames:      false,
			SamplesPerSecond:       20,
			MapScaleFactor:         0,
			KernelVersionCheck:     true,
			BPFVerifierLogLevel:    0,
			ProbabilisticInterval:  100,
			ProbabilisticThreshold: 100,
		})
		require.NoError(b, err)

		b.StopTimer()
		tr.Close()
		b.StartTimer()
	}
}
