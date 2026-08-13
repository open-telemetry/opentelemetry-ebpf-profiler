//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer_test

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/probes/crash"
	"go.opentelemetry.io/ebpf-profiler/probes/oom"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// capturedEvent is a single symbolized trace event recorded by captureReporter.
type capturedEvent struct {
	sampleType string
	pid        libpf.PID
	tid        libpf.PID
	comm       string
	value      int64
	frames     []string
}

// captureReporter implements reporter.TraceReporter and records every symbolized
// trace it receives so tests can assert on probe-produced traces.
type captureReporter struct {
	mu     sync.Mutex
	events []capturedEvent
}

func (r *captureReporter) ReportTraceEvent(trace *libpf.Trace,
	meta *samples.TraceEventMeta) error {
	sampleType := "<unknown>"
	if meta.ProfileType != nil {
		sampleType = meta.ProfileType.SampleType
	}

	frames := make([]string, 0, len(trace.Frames))
	for _, f := range trace.Frames {
		fr := f.Value()
		frames = append(frames, formatE2EFrame(&fr))
	}

	r.mu.Lock()
	r.events = append(r.events, capturedEvent{
		sampleType: sampleType,
		pid:        meta.PID,
		tid:        meta.TID,
		comm:       meta.Comm.String(),
		value:      meta.Value,
		frames:     frames,
	})
	r.mu.Unlock()
	return nil
}

// waitForEvent polls for the first captured event of sampleType belonging to pid,
// until the deadline elapses.
func (r *captureReporter) waitForEvent(sampleType string, pid int,
	timeout time.Duration) (capturedEvent, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		for _, e := range r.events {
			if e.sampleType == sampleType && int(e.pid) == pid {
				r.mu.Unlock()
				return e, true
			}
		}
		r.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	return capturedEvent{}, false
}

// formatE2EFrame renders a symbolized frame as a human-readable line, tagging
// kernel frames so the split between kernel and user stack is visible.
func formatE2EFrame(frame *libpf.Frame) string {
	tag := ""
	switch frame.Type {
	case libpf.KernelFrame:
		tag = "[kernel] "
	case libpf.PythonFrame:
		tag = "[python] "
	case libpf.NativeFrame:
		tag = "[native] "
	}
	if frame.Type.IsError() {
		return fmt.Sprintf("%s<error code %d>", tag, frame.AddressOrLineno)
	}
	if frame.FunctionName != libpf.NullString {
		return fmt.Sprintf("%s%s+%d in %s:%d%s", tag,
			frame.FunctionName, frame.FunctionOffset,
			frame.SourceFile, frame.SourceLine, formatMappingMeta(frame))
	}
	if frame.Mapping.Valid() {
		mf := frame.Mapping.Value().File.Value()
		return fmt.Sprintf("%s%s+0x%x%s", tag, mf.FileName, frame.AddressOrLineno,
			formatMappingMeta(frame))
	}
	return fmt.Sprintf("%s0x%x", tag, frame.AddressOrLineno)
}

// formatMappingMeta renders the per-frame executable mapping metadata the
// profiler attaches to each native frame: the content-addressed FileID and,
// when present, the GNU and Go build IDs, plus the mapping's file-virtual
// address range and file offset. Frames without a backing file mapping
// (kernel, interpreted, error) return "".
func formatMappingMeta(frame *libpf.Frame) string {
	if !frame.Mapping.Valid() {
		return ""
	}
	m := frame.Mapping.Value()
	mf := m.File.Value()
	s := fmt.Sprintf(" {fileID=%s", mf.FileID.StringNoQuotes())
	if mf.GnuBuildID != "" {
		s += " gnuBuildID=" + mf.GnuBuildID
	}
	if mf.GoBuildID != "" {
		s += " goBuildID=" + mf.GoBuildID
	}
	s += fmt.Sprintf(" map=[0x%x-0x%x)+0x%x}", uint64(m.Start), uint64(m.End), m.FileOffset)
	return s
}

// startSampledTracer builds a tracer with the perf CPU sampler running (so
// running processes are discovered and their mappings cached, a precondition
// for the probes to emit fully symbolized traces) and pumps received traces
// through HandleTrace so they reach rep.
func startSampledTracer(ctx context.Context, t *testing.T,
	rep *captureReporter) *tracer.Tracer {
	t.Helper()

	tr, err := tracer.NewTracer(ctx, &tracer.Config{
		Intervals:              &mockIntervals{},
		InterpretersConfig:     interpreterconfig.AllInterpreters(),
		SamplesPerSecond:       99,
		MapScaleFactor:         0,
		KernelVersionCheck:     true,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		// A non-zero OffCPUThreshold loads the kprobe tail-call unwinder chain at
		// startup, which Enable requires to attach custom probes. We do not start
		// off-CPU profiling, so this only wires up the chain.
		OffCPUThreshold: math.MaxUint32,
		VerboseMode:     false,
		// The test host runs inside a PID namespace; translation makes the tracer
		// resolve the same PIDs we observe and is required for its self-analysis.
		PIDNamespaceTranslation: true,
		TraceReporter:           rep,
	})
	require.NoError(t, err)

	traceChan := make(chan *libpf.EbpfTrace, 64)
	require.NoError(t, tr.StartMapMonitors(ctx, traceChan))
	tr.StartPIDEventProcessor(ctx)

	require.NoError(t, tr.AttachTracer(nil))
	require.NoError(t, tr.EnableProfiling())

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case bpfTrace := <-traceChan:
				if bpfTrace != nil {
					tr.HandleTrace(bpfTrace)
				}
			}
		}
	}()

	return tr
}

// buildNativeHelper compiles src (C source) into an executable in the test's
// temp dir and returns its path.
func buildNativeHelper(t *testing.T, name, src string) string {
	t.Helper()
	dir := t.TempDir()
	srcPath := filepath.Join(dir, name+".c")
	binPath := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(srcPath, []byte(src), 0o644))

	cc := "cc"
	// -O0 keeps the source structure close to the trace; symbols come from the
	// default (unstripped) symbol table.
	out, err := exec.Command(cc, "-O0", "-g", "-o", binPath, srcPath).CombinedOutput()
	require.NoErrorf(t, err, "compiling %s failed: %s", name, out)
	return binPath
}

// crasherSrc busy-loops for a few seconds (so the sampler discovers it) then
// dereferences a null pointer, raising SIGSEGV whose default action is a core
// dump — the exact path do_coredump (the crash probe) hooks.
const crasherSrc = `
#include <time.h>
#include <sys/resource.h>
int main(void) {
  // Disable core dump writing to avoid filling /tmp; the do_coredump kprobe
  // still fires at function entry, before the RLIMIT_CORE check.
  struct rlimit rl = {0, 0};
  setrlimit(RLIMIT_CORE, &rl);
  time_t start = time(0);
  volatile unsigned long x = 0;
  while (time(0) - start < 3) { x++; }
  volatile int *p = 0;
  *p = 42;
  return 0;
}
`

// e2eSubprocessEnv marks a re-executed child process that runs a single e2e test.
const e2eSubprocessEnv = "PROBE_E2E_IN_SUBPROCESS"

// Creating more than one full Tracer within a single process is
// unreliable: the kernel system-analysis step performed by NewTracer can fail
// for the second tracer.
func isolateInSubprocess(t *testing.T) bool {
	if os.Geteuid() != 0 {
		t.Skip("e2e test requires root")
	}
	if os.Getenv(e2eSubprocessEnv) == "1" {
		return false // we are the child: run the test body.
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	// Re-exec via /proc/self/exe rather than os.Args[0]: the former points at the
	// running binary's inode and execs correctly even if the on-disk test binary
	// was moved or deleted while the run is in progress. os.Args[0] would fail
	// with "no such file or directory" in that case.
	cmd := exec.CommandContext(ctx, "/proc/self/exe",
		"-test.run", "^"+t.Name()+"$", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), e2eSubprocessEnv+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("--- isolated subprocess output for %s ---\n%s", t.Name(), out)
	require.NoErrorf(t, err, "isolated subprocess for %s failed", t.Name())
	return true
}

// TestCrashProbeProducesTrace enables the crash probe on its own tracer and
// triggers a real SIGSEGV, asserting a symbolized crash_event trace is produced.
// The test isolates itself in a subprocess (see isolateInSubprocess).
func TestCrashProbeProducesTrace(t *testing.T) {
	if isolateInSubprocess(t) {
		return
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rep := &captureReporter{}
	tr := startSampledTracer(ctx, t, rep)
	defer tr.Close()

	crashProbe, err := crash.New(crash.Config{})
	require.NoError(t, err)
	require.NoError(t, tr.Enable(ctx, crashProbe))

	runCrashWorkload(t, rep)
}

// pythonCrasherSrc busy-loops in pure Python (so the profiler discovers and
// classifies the process as a Python interpreter) and then crashes *inside
// native code* by dereferencing a null pointer via ctypes. The crash therefore
// happens with both native C-extension frames and Python interpreter frames on
// the stack, exercising the interleaved unwinder.
// The busy loop runs inside the *deepest* Python function so the entire call
// chain (main -> level_one -> level_two -> level_three) stays on the stack for
// the whole sampling window. Python frames symbolize by reading interpreter
// code objects from live process memory and caching the result; functions that
// only execute for an instant right before the crash are never sampled, so
// their frames come back unsymbolized. Keeping them on-stack lets the perf
// sampler observe and cache them, so they resolve in the post-mortem crash
// trace too.
const pythonCrasherSrc = `
import ctypes, resource, time

# Avoid writing a core file; do_coredump still fires at kprobe entry.
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

def level_three(deadline):
    x = 0
    while time.time() < deadline:
        for _ in range(200000):
            x += 1
    # Read a C string at address 0 -> SIGSEGV inside libc, called from native
    # ctypes/libffi, called from the CPython eval loop.
    ctypes.string_at(0)

def level_two(deadline):
    level_three(deadline)

def level_one(deadline):
    level_two(deadline)

def main():
    level_one(time.time() + 4.0)

main()
`

// TestCrashProbePythonInterleavedTrace runs a Python program that crashes inside
// native code and asserts the crash probe captures a single interleaved trace
// containing kernel frames, native frames, and Python interpreter frames.
// The test isolates itself in a subprocess (see isolateInSubprocess).
func TestCrashProbePythonInterleavedTrace(t *testing.T) {
	if isolateInSubprocess(t) {
		return
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rep := &captureReporter{}
	tr := startSampledTracer(ctx, t, rep)
	defer tr.Close()

	crashProbe, err := crash.New(crash.Config{})
	require.NoError(t, err)
	require.NoError(t, tr.Enable(ctx, crashProbe))

	runPythonCrashWorkload(t, rep)
}

func runPythonCrashWorkload(t *testing.T, rep *captureReporter) {
	dir := t.TempDir()
	script := filepath.Join(dir, "crasher.py")
	require.NoError(t, os.WriteFile(script, []byte(pythonCrasherSrc), 0o644))

	cmd := exec.Command("python3", script)
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	t.Logf("started python crasher pid=%d, waiting for native segfault", pid)

	_ = cmd.Wait()

	event, ok := rep.waitForEvent("crash_event", pid, 6*time.Second)
	require.Truef(t, ok, "did not receive a crash_event trace for pid %d", pid)

	t.Logf("=== crash_event trace: pid=%d tid=%d comm=%q value=%d frames=%d ===",
		event.pid, event.tid, event.comm, event.value, len(event.frames))
	var haveKernel, havePython bool
	for i, f := range event.frames {
		t.Logf("  #%02d %s", i, f)
		if strings.Contains(f, "[kernel]") {
			haveKernel = true
		}
		if strings.Contains(f, "[python]") {
			havePython = true
		}
	}
	require.NotEmpty(t, event.frames, "python crash trace has no frames")
	require.True(t, haveKernel, "expected kernel frames in the interleaved trace")
	require.True(t, havePython,
		"expected Python interpreter frames in the interleaved trace "+
			"(process may not have been classified as Python in time)")
}

// TestOOMProbeProducesTrace enables the OOM probe on its own tracer and triggers
// a real cgroup OOM kill, asserting a symbolized oom_event trace is produced.
// The test isolates itself in a subprocess (see isolateInSubprocess).
func TestOOMProbeProducesTrace(t *testing.T) {
	if isolateInSubprocess(t) {
		return
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	rep := &captureReporter{}
	tr := startSampledTracer(ctx, t, rep)
	defer tr.Close()

	oomProbe, err := oom.New(oom.Config{})
	require.NoError(t, err)
	require.NoError(t, tr.Enable(ctx, oomProbe))

	runOOMWorkload(t, rep)
}

func runCrashWorkload(t *testing.T, rep *captureReporter) {
	crasher := buildNativeHelper(t, "crasher", crasherSrc)
	cmd := exec.Command(crasher)
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	t.Logf("started crasher pid=%d, waiting for it to segfault", pid)

	// The process segfaults on its own after its busy loop.
	_ = cmd.Wait()

	event, ok := rep.waitForEvent("crash_event", pid, 5*time.Second)
	require.Truef(t, ok, "did not receive a crash_event trace for pid %d", pid)

	t.Logf("=== crash_event trace: pid=%d tid=%d comm=%q value=%d frames=%d ===",
		event.pid, event.tid, event.comm, event.value, len(event.frames))
	for i, f := range event.frames {
		t.Logf("  #%02d %s", i, f)
	}
	require.NotEmpty(t, event.frames, "crash trace has no frames")
}

// hogSrc waits for a go-ahead byte on stdin (so the parent can place it in a
// memory-limited cgroup first), busy-loops briefly to get discovered, then
// allocates and touches memory until the cgroup OOM killer kills it.
const hogSrc = `
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
int main(void) {
  char c;
  if (write(1, "R", 1) != 1) return 1;
  if (read(0, &c, 1) != 1) return 1;
  time_t start = time(0);
  volatile unsigned long x = 0;
  while (time(0) - start < 2) { x++; }
  size_t chunk = 4 * 1024 * 1024;
  for (;;) {
    char *p = malloc(chunk);
    if (!p) return 1;
    memset(p, 1, chunk);
    usleep(20000);
  }
  return 0;
}
`

func writeCgroupFile(t *testing.T, path, val string) error {
	t.Helper()
	return os.WriteFile(path, []byte(val), 0o644)
}

func runOOMWorkload(t *testing.T, rep *captureReporter) {
	// Create a dedicated memory-limited cgroup so the OOM kill is contained.
	const cgRoot = "/sys/fs/cgroup"
	// Best-effort: ensure the memory controller is delegated to children.
	_ = writeCgroupFile(t, filepath.Join(cgRoot, "cgroup.subtree_control"), "+memory")
	cgDir := filepath.Join(cgRoot, "probe_e2e_oom")
	require.NoError(t, os.Mkdir(cgDir, 0o755))
	defer func() { _ = os.Remove(cgDir) }()
	require.NoError(t, writeCgroupFile(t, filepath.Join(cgDir, "memory.max"), "128M"))
	_ = writeCgroupFile(t, filepath.Join(cgDir, "memory.swap.max"), "0")

	hog := buildNativeHelper(t, "hog", hogSrc)
	cmd := exec.Command(hog)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err)
	stdout, err := cmd.StdoutPipe()
	require.NoError(t, err)
	require.NoError(t, cmd.Start())
	pid := cmd.Process.Pid
	t.Logf("started hog pid=%d", pid)

	// Wait for readiness marker, then move it into the memory cgroup.
	buf := make([]byte, 1)
	_, err = stdout.Read(buf)
	require.NoError(t, err)
	require.NoError(t, writeCgroupFile(t, filepath.Join(cgDir, "cgroup.procs"),
		strconv.Itoa(pid)))
	// Release the hog: it will busy-loop, then allocate until OOM-killed.
	_, err = stdin.Write([]byte("g"))
	require.NoError(t, err)

	_ = cmd.Wait()
	t.Logf("hog exited (expected OOM kill)")

	event, ok := rep.waitForEvent("oom_event", pid, 8*time.Second)
	if !ok {
		// The oom probe records the task in the OOM path; if PID matching misses
		// (e.g. kill attributed to a kernel thread), fall back to any oom_event.
		rep.mu.Lock()
		for _, e := range rep.events {
			if e.sampleType == "oom_event" {
				event, ok = e, true
				break
			}
		}
		rep.mu.Unlock()
	}
	require.True(t, ok, "did not receive an oom_event trace")

	t.Logf("=== oom_event trace: pid=%d tid=%d comm=%q value=%d frames=%d ===",
		event.pid, event.tid, event.comm, event.value, len(event.frames))
	for i, f := range event.frames {
		t.Logf("  #%02d %s", i, f)
	}
	require.NotEmpty(t, event.frames, "oom trace has no frames")
}
