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
func testRecord(t *testing.T, originID uint16) []byte {
	t.Helper()
	// With no mapping and no interpreter instances, symbolization falls
	// back to a raw native frame.
	frame := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, 21)
	frame[1] = 0x4567
	end := uint16(8 * len(frame))
	header := support.Trace{
		Pid:               123,
		Origin:            originID,
		Frame_data_end:    end,
		Thread_label_end:  end,
		Golang_label_end:  end,
		Variable_data_end: end,
		Num_frames:        1,
	}
	return append(pfunsafe.FromPointer(&header), pfunsafe.FromSlice(frame)...)
}

// TestHandleTraceSyncProcessesSubmittedTrace verifies that the synchronous
// trace path decodes, symbolizes and reports a record before it returns.
func TestHandleTraceSyncProcessesSubmittedTrace(t *testing.T) {
	capture := &traceCapture{}
	pm, originID := newTestWorkerPM(t, capture)

	require.NoError(t, pm.HandleTraceSync(testRecord(t, originID)))

	require.Len(t, capture.traces, 1)
	require.Len(t, capture.traces[0].Frames, 1)
	frame := capture.traces[0].Frames[0].Value()
	require.Equal(t, libpf.NativeFrame, frame.Type)
	require.Equal(t, libpf.AddressOrLineno(21), frame.AddressOrLineno)
}

// TestBatchBoundaryWaitsForQueuedTraces verifies that the process exit
// cleanup does not run before the traces submitted before the batch
// boundary were processed.
func TestBatchBoundaryWaitsForQueuedTraces(t *testing.T) {
	capture := &traceCapture{}
	pm, originID := newTestWorkerPM(t, capture)

	pid := libpf.PID(42)
	pm.mu.Lock()
	pm.exitEvents[pid] = times.KTime(100)
	pm.pidToProcessInfo[pid] = &processInfo{}
	pm.mu.Unlock()

	pm.HandleTrace(testRecord(t, originID))
	pm.BatchSubmitted()
	// Await the boundary: it applies only after all prior operations.
	boundary := traceOp{done: make(chan struct{})}
	pm.submit(boundary)
	select {
	case <-boundary.done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for the batch boundary")
	}

	pm.mu.RLock()
	_, processLeft := pm.pidToProcessInfo[pid]
	_, exitLeft := pm.exitEvents[pid]
	pm.mu.RUnlock()
	require.False(t, processLeft, "process exit event was not cleaned up")
	require.False(t, exitLeft, "process exit event was not cleaned up")
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
