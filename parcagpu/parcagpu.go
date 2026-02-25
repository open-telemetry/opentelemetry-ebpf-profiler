package parcagpu // import "go.opentelemetry.io/ebpf-profiler/parcagpu"

import (
	"context"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/processmanager"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// Start starts a goroutine that reads GPU timing events and returns a TraceInterceptor
// that diverts CUDA traces (post-symbolization) into the GPU fixer.
// Completed CUDA traces are reported directly via rep.
func Start(ctx context.Context, tr *tracer.Tracer,
	rep reporter.TraceReporter) processmanager.TraceInterceptor {
	gpuTimingEvents := tr.GetEbpfMaps()["cuda_timing_events"]

	// Per-CPU buffer size for timing events. CuptiTimingEvent is ~300 bytes,
	// so 1MB allows ~3400 events per CPU before overflow.
	eventReader, err := perf.NewReader(gpuTimingEvents, 1024*1024 /* perCPUBufferSize */)
	if err != nil {
		log.Fatalf("Failed to setup perf reporting via %s: %v", gpuTimingEvents, err)
	}

	var lostEventsCount, readErrorCount, noDataCount atomic.Uint64

	// processBatch processes a batch of timing events and reports completed traces.
	processBatch := func(batch []gpu.CuptiTimingEvent) {
		outputs := gpu.AddTimes(batch)
		for i := range outputs {
			if err := rep.ReportTraceEvent(outputs[i].Trace, outputs[i].Meta); err != nil {
				log.Errorf("[parcagpu] failed to report CUDA trace: %v", err)
			}
		}
	}

	const batchSize = 100
	go func() {
		var data perf.Record
		batch := make([]gpu.CuptiTimingEvent, 0, batchSize)

		logTicker := time.NewTicker(5 * time.Second)
		defer logTicker.Stop()

		clearTicker := time.NewTicker(2 * time.Second)
		defer clearTicker.Stop()

		for {
			select {
			case <-logTicker.C:
				lost := lostEventsCount.Swap(0)
				readErr := readErrorCount.Swap(0)
				noData := noDataCount.Swap(0)
				if lost > 0 || readErr > 0 || noData > 0 {
					log.Warnf("[cuda] timing event reader: lost=%d readErrors=%d noData=%d",
						lost, readErr, noData)
				}
			case <-clearTicker.C:
				// Periodically clean up all GPU trace fixers and report metrics.
				// MaybeClearAll returns metrics for the caller to report via AddSlice,
				// avoiding duplicate-metric warnings from the metrics system.
				metrics.AddSlice(gpu.MaybeClearAll())
			case <-ctx.Done():
				eventReader.Close()
				return
			default:
				if err := eventReader.ReadInto(&data); err != nil {
					readErrorCount.Add(1)
					continue
				}
				if data.LostSamples != 0 {
					lostEventsCount.Add(data.LostSamples)
					continue
				}
				if len(data.RawSample) == 0 {
					noDataCount.Add(1)
					continue
				}
				// Copy event into batch since data.RawSample is reused
				ev := (*gpu.CuptiTimingEvent)(unsafe.Pointer(&data.RawSample[0]))
				batch = append(batch, *ev)
				if len(batch) >= batchSize {
					go processBatch(batch)
					batch = make([]gpu.CuptiTimingEvent, 0, batchSize)
				}
			}
		}
	}()

	// Return the interceptor function that diverts CUDA traces post-symbolization.
	return func(trace *libpf.Trace, meta *samples.TraceEventMeta,
		rawTrace *libpf.EbpfTrace) bool {
		if meta.Origin != support.TraceOriginCuda {
			return false
		}

		// Extract correlation ID and CBID from the raw BPF trace (not the
		// symbolized trace, which may be a cached template with stale values).
		var correlationID uint32
		var cbid int32
		for frames := libpf.EbpfFrame(rawTrace.FrameData); len(frames) > 0; frames = frames[frames.Length():] {
			if frames.Type() == libpf.CUDAKernelFrame {
				lineno := frames.Variable(0)
				correlationID = uint32(lineno)
				cbid = int32(lineno >> 32)
				break
			}
		}

		// Find the CUDA kernel frame index in the symbolized trace.
		cudaFrameIdx := -1
		for i, uniqueFrame := range trace.Frames {
			if uniqueFrame.Value().Type == libpf.CUDAKernelFrame {
				cudaFrameIdx = i
				break
			}
		}
		if cudaFrameIdx < 0 {
			log.Errorf("[parcagpu] CUDA trace has no CUDAKernelFrame")
			return false
		}

		st := &gpu.SymbolizedCudaTrace{
			Trace:         trace,
			Meta:          meta,
			CUDAFrameIdx:  cudaFrameIdx,
			CorrelationID: correlationID,
			CBID:          cbid,
		}

		outputs := gpu.AddTrace(st)
		for i := range outputs {
			if err := rep.ReportTraceEvent(outputs[i].Trace, outputs[i].Meta); err != nil {
				log.Errorf("[parcagpu] failed to report CUDA trace: %v", err)
			}
		}

		return true // consumed
	}
}
