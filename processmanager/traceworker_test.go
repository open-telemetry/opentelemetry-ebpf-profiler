// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/times"
)

// newTestWorkerPM returns a process manager wired to the given reporter and
// its registered sampling origin ID.
func newTestWorkerPM(t *testing.T, reporter *traceCapture) (*ProcessManager, uint16) {
	t.Helper()
	pmv, err := New(t.Context(), Config{
		InterpretersConfig:    interpreterconfig.NoInterpreters(),
		MonitorInterval:       time.Hour,
		ExecutableUnloadDelay: time.Hour,
		EbpfHandler:           &testEbpfHandler{},
		IncludeEnvVars:        libpf.Set[string]{},
		TraceReporter:         reporter,
	})
	require.NoError(t, err)
	originID, err := pmv.origins.Register(&OriginEntry{
		Meta: &samples.TypeMetadata{
			SampleTypes:  []samples.SampleType{{Type: "samples", Unit: "count"}},
			AppendValues: samples.AppendFirstContextValue,
		},
	})
	require.NoError(t, err)
	t.Cleanup(pmv.Close)
	return pmv, originID
}

// testRecord builds a minimal valid trace record with a single native frame.
func testRecord(t *testing.T, originID uint16, pid libpf.PID) []byte {
	t.Helper()
	// With no mapping and no interpreter instances, symbolization falls
	// back to a raw native frame.
	frame := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, 21)
	frame[1] = 0x4567
	end := uint16(8 * len(frame))
	header := support.Trace{
		Pid:               uint32(pid),
		Origin:            originID,
		Frame_data_end:    end,
		Thread_label_end:  end,
		Golang_label_end:  end,
		Variable_data_end: end,
		Num_frames:        1,
	}
	return append(pfunsafe.FromPointer(&header), pfunsafe.FromSlice(frame)...)
}

// awaitQuiescence waits until the exit cleanup watermark reached ckptTime,
// which implies the traces queued before the boundary were processed.
func awaitQuiescence(t *testing.T, pm *ProcessManager, ckptTime times.KTime) {
	t.Helper()
	require.Eventually(t, func() bool {
		return times.KTime(pm.exitWatermark.Load()) >= ckptTime
	}, 10*time.Second, time.Millisecond, "timed out waiting for quiescence")
}

// TestHandleTraceSyncProcessesSubmittedTrace verifies that the synchronous
// trace path decodes, symbolizes and reports a record before it returns.
func TestHandleTraceSyncProcessesSubmittedTrace(t *testing.T) {
	capture := &traceCapture{}
	pm, originID := newTestWorkerPM(t, capture)

	require.NoError(t, pm.HandleTraceSync(testRecord(t, originID, 123)))

	require.Len(t, capture.traces, 1)
	require.Len(t, capture.traces[0].Frames, 1)
	frame := capture.traces[0].Frames[0].Value()
	require.Equal(t, libpf.NativeFrame, frame.Type)
	require.Equal(t, libpf.AddressOrLineno(21), frame.AddressOrLineno)
}

// TestBatchBoundaryWaitsForQueuedTraces verifies that the exit cleanup runs
// only after the traces submitted before the boundary were processed.
func TestBatchBoundaryWaitsForQueuedTraces(t *testing.T) {
	pid := libpf.PID(42)
	ckptTime := times.KTime(1000)

	// exitPending records, at report time, whether the exit of pid was
	// still waiting for cleanup.
	var exitPending bool
	capture := &traceCapture{}
	pm, originID := newTestWorkerPM(t, capture)
	capture.onReport = func() {
		pm.mu.RLock()
		_, pending := pm.exitEvents[pid]
		pm.mu.RUnlock()
		exitPending = pending
	}

	pm.mu.Lock()
	pm.exitEvents[pid] = ckptTime
	pm.pidToProcessInfo[pid] = &processInfo{}
	pm.mu.Unlock()

	pm.HandleTrace(testRecord(t, originID, pid))
	pm.BatchSubmitted(ckptTime)
	// Cleanup applies only after the trace was processed.
	awaitQuiescence(t, pm, ckptTime)

	pm.mu.RLock()
	_, processLeft := pm.pidToProcessInfo[pid]
	_, exitLeft := pm.exitEvents[pid]
	pm.mu.RUnlock()
	require.False(t, processLeft, "process exit event was not cleaned up")
	require.False(t, exitLeft, "process exit event was not cleaned up")
	require.True(t, exitPending,
		"cleanup ran before the trace submitted before the boundary")
}

// TestBatchBoundaryKeepsNewerExits verifies that an exit observed after the
// boundary watermark survives the cleanup.
func TestBatchBoundaryKeepsNewerExits(t *testing.T) {
	pid := libpf.PID(42)
	capture := &traceCapture{}
	pm, _ := newTestWorkerPM(t, capture)

	pm.mu.Lock()
	pm.exitEvents[pid] = times.KTime(1001)
	pm.pidToProcessInfo[pid] = &processInfo{}
	pm.mu.Unlock()

	pm.BatchSubmitted(times.KTime(1000))
	awaitQuiescence(t, pm, times.KTime(1000))

	pm.mu.RLock()
	_, processLeft := pm.pidToProcessInfo[pid]
	_, exitLeft := pm.exitEvents[pid]
	pm.mu.RUnlock()
	require.True(t, processLeft, "exit newer than the watermark was cleaned up")
	require.True(t, exitLeft, "exit newer than the watermark was cleaned up")
}

// TestHandleTraceRejectsMalformedRecords verifies the fatal record error
// surface of the drop point.
func TestHandleTraceRejectsMalformedRecords(t *testing.T) {
	capture := &traceCapture{}
	pm, _ := newTestWorkerPM(t, capture)

	require.ErrorIs(t, pm.HandleTrace(make([]byte, support.Sizeof_TraceHeader-1)),
		ErrRecordTooSmall)
	require.ErrorIs(t, pm.HandleTrace(make([]byte, traceRecordMaxSize+1)),
		ErrRecordUnexpectedSize)
	require.Empty(t, capture.traces)
}
