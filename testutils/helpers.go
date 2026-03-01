package testutils // import "go.opentelemetry.io/ebpf-profiler/testutils"

import (
	"bufio"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/tracer"
	tracertypes "go.opentelemetry.io/ebpf-profiler/tracer/types"
)

type MockIntervals struct{}

func (f MockIntervals) MonitorInterval() time.Duration       { return 1 * time.Second }
func (f MockIntervals) TracePollInterval() time.Duration     { return 250 * time.Millisecond }
func (f MockIntervals) PIDCleanupInterval() time.Duration    { return 1 * time.Second }
func (f MockIntervals) ExecutableUnloadDelay() time.Duration { return 1 * time.Second }

type MockReporter struct{}

func (f MockReporter) ExecutableKnown(_ libpf.FileID) bool {
	return true
}

type TraceEvent struct {
	Trace *libpf.Trace
	Meta  *samples.TraceEventMeta
}

type traceReporter struct {
	traceEventChan chan<- TraceEvent
}

func (tr *traceReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	tr.traceEventChan <- TraceEvent{
		Trace: trace,
		Meta:  meta,
	}
	return nil
}

func StartTracer(ctx context.Context, t *testing.T, et tracertypes.IncludedTracers,
	printBpfLogs bool) (<-chan TraceEvent, *tracer.Tracer) {
	traceCh := make(chan TraceEvent)
	tr := &traceReporter{
		traceEventChan: traceCh,
	}

	trc, err := tracer.NewTracer(ctx, &tracer.Config{
		TraceReporter:          tr,
		Intervals:              &MockIntervals{},
		IncludeTracers:         et,
		SamplesPerSecond:       20,
		ProbabilisticInterval:  100,
		ProbabilisticThreshold: 100,
		OffCPUThreshold:        uint32(math.MaxUint32 / 100),
		VerboseMode:            true,
	})
	require.NoError(t, err)

	if printBpfLogs {
		go readTracePipe(ctx)
	}

	trc.StartPIDEventProcessor(ctx)

	err = trc.AttachTracer()
	require.NoError(t, err)
	log.Info("Attached tracer program")

	err = trc.EnableProfiling()
	require.NoError(t, err)
	log.Info("Enabled profiling")

	err = trc.AttachSchedMonitor()
	require.NoError(t, err)
	log.Info("Attached sched monitor")

	// Spawn monitors for the various result maps
	ebpfTraceCh := make(chan *libpf.EbpfTrace)

	err = trc.StartMapMonitors(ctx, ebpfTraceCh)
	require.NoError(t, err)

	go func() {
		for {
			select {
			case trace := <-ebpfTraceCh:
				if trace != nil {
					trc.HandleTrace(trace)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	return traceCh, trc
}

func getTracePipe() (*os.File, error) {
	for _, mnt := range []string{
		"/sys/kernel/debug/tracing",
		"/sys/kernel/tracing",
		"/tracing",
		"/trace"} {
		t, err := os.Open(mnt + "/trace_pipe")
		if err == nil {
			return t, nil
		}
		log.Errorf("Could not open trace_pipe at %s: %s", mnt, err)
	}
	return nil, os.ErrNotExist
}

func readTracePipe(ctx context.Context) {
	tp, err := getTracePipe()
	if err != nil {
		log.Warn("Could not open trace_pipe, check that debugfs is mounted")
		return
	}

	// When we're done kick ReadString out of blocked I/O.
	go func() {
		<-ctx.Done()
		_ = tp.Close()
	}()

	r := bufio.NewReader(tp)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) {
				continue
			}
			if errors.Is(err, os.ErrClosed) {
				return
			}
			log.Error(err)
			return
		}
		line = strings.TrimSpace(line)
		if line != "" {
			log.Infof("%s", line)
		}
	}
}

func IsRoot() bool {
	return os.Geteuid() == 0
}
