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
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tracer"
)

// Start starts two goroutines that filter traces coming from ebpf and match them up with timing
// information coming from the parcagpu usdt probes.
func Start(ctx context.Context, traceInCh <-chan *libpf.EbpfTrace,
	tr *tracer.Tracer) chan *libpf.EbpfTrace {
	gpuTimingEvents := tr.GetEbpfMaps()["cuda_timing_events"]
	traceOutChan := make(chan *libpf.EbpfTrace, 1024)

	// Read traces coming from ebpf and send normal traces through
	go func() {
		timer := time.NewTicker(1 * time.Second)
		defer timer.Stop()

		for {
			select {
			case <-timer.C:
				// Periodically clean up all GPU trace fixers and report metrics
				gpu.MaybeClearAll()
			case <-ctx.Done():
				return
			case t := <-traceInCh:
				if t != nil && t.Origin == support.TraceOriginCuda {
					if err := gpu.AddTrace(t, traceOutChan); err != nil {
						log.Errorf("[parcagpu] failed to add trace for PID %d: %v", t.PID, err)
					}
				} else {
					traceOutChan <- t
				}
			}
		}
	}()

	// Per-CPU buffer size for timing events. CuptiTimingEvent is ~300 bytes,
	// so 1MB allows ~3400 events per CPU before overflow.
	eventReader, err := perf.NewReader(gpuTimingEvents, 1024*1024 /* perCPUBufferSize */)
	if err != nil {
		log.Fatalf("Failed to setup perf reporting via %s: %v", gpuTimingEvents, err)
	}

	var lostEventsCount, readErrorCount, noDataCount atomic.Uint64

	// processBatch processes a batch of timing events in parallel.
	processBatch := func(batch []gpu.CuptiTimingEvent) {
		gpu.AddTimes(batch, traceOutChan)
	}

	const batchSize = 100
	go func() {
		var data perf.Record
		batch := make([]gpu.CuptiTimingEvent, 0, batchSize)

		logTicker := time.NewTicker(5 * time.Second)
		defer logTicker.Stop()
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
			case <-ctx.Done():
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

	return traceOutChan
}
