package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"bytes"
	"fmt"
	"strconv"
	"sync"
	"unique"
	"unsafe"

	"github.com/ianlancetaylor/demangle"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
)

const (
	// eBPF program names for USDT probes
	// These correspond to the function names in cuda.ebpf.c, not the SEC() paths
	USDTProgCudaCorrelation = "cuda_correlation"
	USDTProgCudaKernel      = "cuda_kernel_exec"
	USDTProgCudaProbe       = "cuda_probe"
)

var (
	// gpuFixers maps PID to gpuTraceFixer
	gpuFixers sync.Map
)

// SymbolizedCudaTrace holds a symbolized trace awaiting GPU timing information.
// The CPU frames are already symbolized; only the CUDA kernel frame
// needs the kernel name from the timing event.
type SymbolizedCudaTrace struct {
	Trace         *libpf.Trace
	Meta          *samples.TraceEventMeta
	CUDAFrameIdx  int // index of CUDAKernelFrame in Trace.Frames
	CorrelationID uint32
	CBID          int32
}

// CudaTraceOutput is a fully completed CUDA trace ready for reporting.
// For non-graph launches the pointers alias the SymbolizedCudaTrace directly.
// For graph launches they point to copies since the original is reused.
type CudaTraceOutput struct {
	Trace *libpf.Trace
	Meta  *samples.TraceEventMeta
}

// gpuTraceFixer matches traces with timing information for a specific PID.
// We use a single fixer per PID because CUDA correlation IDs are unique per process
// across all devices and streams.
// See: https://docs.nvidia.com/cupti/api/structCUpti__ActivityKernel.html
// The correlationId field: "Each function invocation is assigned a unique correlation ID
// that is identical to the correlation ID in the driver or runtime API activity record
// that launched the kernel."
type gpuTraceFixer struct {
	mu                  sync.Mutex
	timesAwaitingTraces map[uint32][]CuptiTimingEvent   // keyed by correlation ID
	tracesAwaitingTimes map[uint32]*SymbolizedCudaTrace // keyed by correlation ID
	maxCorrelationId    uint32                          // track highest ID for threshold-based clearing
}

type data struct {
	path   string
	link   interpreter.LinkCloser
	probes []pfelf.USDTProbe
}

// Instance is the CUDA interpreter instance
type Instance struct {
	interpreter.InstanceStubs
	path string
	pid  libpf.PID
}

// CuptiTimingEvent is the structure received from eBPF via perf buffer
type CuptiTimingEvent struct {
	Pid                     uint32
	Id                      uint32
	Start, End, GraphNodeId uint64
	Dev, Stream, Graph      uint32
	KernelName              [256]byte
}

func Loader(ebpf interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// We use the existence of the .note.stapsdt section to determine if this is a
	// process that has libparcagpucupti.so loaded.
	probes, err := ef.ParseUSDTProbes()
	if err != nil {
		return nil, err
	}
	if len(probes) > 0 {
		var parcagpuProbes []pfelf.USDTProbe
		for _, probe := range probes {
			if probe.Provider == "parcagpu" {
				parcagpuProbes = append(parcagpuProbes, probe)
			}
		}
		if len(parcagpuProbes) == 0 {
			return nil, nil
		}

		// Filter to only the probes we need
		var requiredProbes []pfelf.USDTProbe
		for _, probe := range parcagpuProbes {
			if probe.Name == "cuda_correlation" || probe.Name == "kernel_executed" {
				requiredProbes = append(requiredProbes, probe)
			}
		}
		if len(requiredProbes) != 2 {
			log.Warnf("parcagpu USDT probes in %s missing required probes (need cuda_correlation and kernel_executed): %v", info.FileName(), parcagpuProbes)
			return nil, nil
		}
		parcagpuProbes = requiredProbes

		log.Debugf("Found parcagpu USDT probes in %s: %v", info.FileName(), parcagpuProbes)

		d := &data{
			path:   info.FileName(),
			probes: parcagpuProbes,
		}

		return d, nil
	}
	return nil, nil
}

func (d *data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID, _ libpf.Address,
	_ remotememory.RemoteMemory) (interpreter.Instance, error) {
	// Maps usdt probe name to ebpf program name.
	// Use the first character of the probe name as a cookie.
	// 'c' -> cuda_correlation
	// 'k' -> cuda_kernel_exec
	cookies := make([]uint64, len(d.probes))
	progNames := make([]string, len(d.probes))
	for i, probe := range d.probes {
		cookies[i] = uint64(probe.Name[0])
		// Map probe names to specific program names for single-shot mode
		switch probe.Name {
		case "cuda_correlation":
			progNames[i] = USDTProgCudaCorrelation
		case "kernel_executed":
			progNames[i] = USDTProgCudaKernel
		default:
			log.Debugf("unknown parcagpu USDT probe name: %s", probe.Name)
		}
	}

	var lc interpreter.LinkCloser
	if d.link == nil {
		var err error
		lc, err = ebpf.AttachUSDTProbes(pid, d.path, USDTProgCudaProbe, d.probes, cookies, progNames)
		if err != nil {
			return nil, err
		}
		log.Debugf("[cuda] parcagpu USDT probes attached for %s", d.path)
		d.link = lc
	} else {
		log.Debugf("[cuda] parcagpu USDT probes already attached for %s", d.path)
	}

	// Create and register fixer for this PID
	fixer := &gpuTraceFixer{
		timesAwaitingTraces: make(map[uint32][]CuptiTimingEvent),
		tracesAwaitingTimes: make(map[uint32]*SymbolizedCudaTrace),
	}

	gpuFixers.Store(pid, fixer)
	return &Instance{
		path: d.path,
		pid:  pid,
	}, nil
}

func (i *Instance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	gpuFixers.Delete(i.pid)
	return nil
}

const (
	CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch                = 514
	CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz           = 515
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000      = 311
	CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000 = 312
)

func isGraphLaunch(cbid int32) bool {
	if cbid < 0 {
		// Driver API callback ids are negative
		switch -cbid {
		case CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch, CUPTI_DRIVER_TRACE_CBID_cuGraphLaunch_ptsz:
			return true
		}
	} else {
		switch cbid {
		case CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_v10000, CUPTI_RUNTIME_TRACE_CBID_cudaGraphLaunch_ptsz_v10000:
			return true
		}
	}
	return false
}

// addTrace is called when a symbolized CUDA trace is received, to match it with timing info.
// Returns completed traces (may be multiple for graph launches).
func (f *gpuTraceFixer) addTrace(st *SymbolizedCudaTrace) []CudaTraceOutput {
	log.Debugf("[cuda] adding trace with id %d cbid %d (0x%x) for pid %d",
		st.CorrelationID, int(st.CBID), uint32(st.CBID), st.Meta.PID)
	f.mu.Lock()
	defer f.mu.Unlock()

	// Update max, detecting wrap-around (new ID much smaller than max means wrap)
	if st.CorrelationID > f.maxCorrelationId || f.maxCorrelationId-st.CorrelationID > 1<<31 {
		f.maxCorrelationId = st.CorrelationID
	}

	var outputs []CudaTraceOutput

	evs, ok := f.timesAwaitingTraces[st.CorrelationID]
	if ok && len(evs) > 0 {
		// Process any timing events that arrived before this trace
		for idx := range evs {
			log.Debugf("[cuda] gpu trace completed id %d cbid %d (0x%x) for pid %d",
				st.CorrelationID, int(st.CBID), uint32(st.CBID), st.Meta.PID)
			outputs = append(outputs, f.prepTrace(st, &evs[idx]))
		}
		// Always delete the key to avoid nil entries accumulating
		delete(f.timesAwaitingTraces, st.CorrelationID)
		// For non-graph launches, we've matched the only timing event, done
		if !isGraphLaunch(st.CBID) {
			return outputs
		}
	}
	// Store trace for future timing events
	f.tracesAwaitingTimes[st.CorrelationID] = st
	return outputs
}

// addTime is called when timing info is received from eBPF, to match it with a trace.
// Caller must hold f.mu.
func (f *gpuTraceFixer) addTime(ev *CuptiTimingEvent) (CudaTraceOutput, bool) {
	// Update max, detecting wrap-around (new ID much smaller than max means wrap)
	if ev.Id > f.maxCorrelationId || f.maxCorrelationId-ev.Id > 1<<31 {
		f.maxCorrelationId = ev.Id
	}

	st, ok := f.tracesAwaitingTimes[ev.Id]
	if ok {
		if ev.Graph == 0 {
			delete(f.tracesAwaitingTimes, ev.Id)
		}
		return f.prepTrace(st, ev), true
	}
	f.timesAwaitingTraces[ev.Id] = append(f.timesAwaitingTraces[ev.Id], *ev)
	return CudaTraceOutput{}, false
}

// fixerStats holds statistics from a single fixer for aggregation.
type fixerStats struct {
	timesLen      int
	tracesLen     int
	timesCleared  int
	tracesCleared int
}

// maybeClear clears the maps if they get too big and returns stats.
// Uses threshold-based clearing: deletes entries with correlation ID < maxCorrelationId - 5000
func (f *gpuTraceFixer) maybeClear() fixerStats {
	f.mu.Lock()
	defer f.mu.Unlock()

	timesLen := len(f.timesAwaitingTraces)
	tracesLen := len(f.tracesAwaitingTimes)

	stats := fixerStats{
		timesLen:  timesLen,
		tracesLen: tracesLen,
	}

	if timesLen > 10000 || tracesLen > 10000 {
		// Keep entries within 5000 of the max correlation ID
		// Use signed distance to handle wrap-around correctly
		for k := range f.timesAwaitingTraces {
			if int32(f.maxCorrelationId-k) > 5000 {
				delete(f.timesAwaitingTraces, k)
			}
		}
		for k := range f.tracesAwaitingTimes {
			if int32(f.maxCorrelationId-k) > 5000 {
				delete(f.tracesAwaitingTimes, k)
			}
		}

		stats.timesCleared = timesLen - len(f.timesAwaitingTraces)
		stats.tracesCleared = tracesLen - len(f.tracesAwaitingTimes)
	}

	return stats
}

var (
	cudaDevice libpf.String
	cudaStream libpf.String
	cudaGraph  libpf.String
	cudaId     libpf.String
)

func init() {
	cudaDevice = libpf.Intern("cuda_device")
	cudaStream = libpf.Intern("cuda_stream")
	cudaGraph = libpf.Intern("cuda_graph")
	cudaId = libpf.Intern("cuda_id")
}

// prepTrace attaches timing information and the demangled kernel name to a symbolized
// CUDA trace, producing a CudaTraceOutput ready for reporting.
func (f *gpuTraceFixer) prepTrace(st *SymbolizedCudaTrace, ev *CuptiTimingEvent) CudaTraceOutput {
	out := CudaTraceOutput{
		Trace: st.Trace,
		Meta:  st.Meta,
	}

	if ev.Graph != 0 {
		// Graphs can have many kernels with same correlation ID.
		// Copy Trace (Frames differ per kernel, Hash differs) and Meta (OffTime differs)
		// since the original st stays in the map for future timing events.
		// CustomLabels are NOT copied: all events for the same correlation ID share
		// identical cuda_device/cuda_stream/cuda_graph values.
		traceCopy := *st.Trace
		traceCopy.Frames = make(libpf.Frames, len(st.Trace.Frames))
		copy(traceCopy.Frames, st.Trace.Frames)
		out.Trace = &traceCopy
		metaCopy := *st.Meta
		out.Meta = &metaCopy
	}

	out.Meta.OffTime = int64(ev.End - ev.Start)
	if out.Trace.CustomLabels == nil {
		out.Trace.CustomLabels = make(map[libpf.String]libpf.String)
	}

	out.Trace.CustomLabels[cudaDevice] = libpf.Intern(strconv.FormatUint(uint64(ev.Dev), 10))
	if ev.Stream != 0 {
		out.Trace.CustomLabels[cudaStream] = libpf.Intern(strconv.FormatUint(uint64(ev.Stream), 10))
	}
	if ev.Graph != 0 {
		out.Trace.CustomLabels[cudaGraph] = libpf.Intern(strconv.FormatUint(uint64(ev.Graph), 10))
		out.Trace.CustomLabels[cudaId] = libpf.Intern(strconv.FormatUint(uint64(ev.Id), 10))
	}

	// Extract kernel name from timing event, demangle, and update the CUDA frame.
	nameBytes := ev.KernelName[:]
	if idx := bytes.IndexByte(nameBytes, 0); idx >= 0 {
		nameBytes = nameBytes[:idx]
	}
	if len(nameBytes) > 0 {
		mangledStr := libpf.Intern(unsafe.String(unsafe.SliceData(nameBytes), len(nameBytes)))
		funcName := mangledStr
		if demStr, err := demangle.ToString(
			mangledStr.String(), demangle.NoParams, demangle.NoEnclosingParams); err == nil {
			funcName = libpf.Intern(demStr)
		}

		fi := st.CUDAFrameIdx
		out.Trace.Frames[fi] = unique.Make(libpf.Frame{
			Type:         out.Trace.Frames[fi].Value().Type,
			FunctionName: funcName,
		})
	}

	// Recompute trace hash since we modified frame[0]
	out.Trace.Hash = traceutil.HashTrace(out.Trace)

	return out
}

// AddTrace is a static function that delegates to the appropriate fixer for the PID.
func AddTrace(st *SymbolizedCudaTrace) []CudaTraceOutput {
	pid := st.Meta.PID
	value, ok := gpuFixers.Load(pid)
	if !ok {
		log.Warnf("no GPU fixer found for PID %d in AddTrace", pid)
		return nil
	}
	fixer := value.(*gpuTraceFixer)
	return fixer.addTrace(st)
}

// addTimeSingle is a static function that delegates to the appropriate fixer for the PID.
func addTimeSingle(ev *CuptiTimingEvent) (CudaTraceOutput, bool) {
	pid := libpf.PID(ev.Pid)
	value, ok := gpuFixers.Load(pid)
	if !ok {
		log.Warnf("no GPU fixer found for PID %d in AddTime", pid)
		return CudaTraceOutput{}, false
	}
	fixer := value.(*gpuTraceFixer)
	fixer.mu.Lock()
	defer fixer.mu.Unlock()
	return fixer.addTime(ev)
}

// AddTimes processes a batch of timing events, taking the lock once per PID.
// Returns all completed traces.
func AddTimes(events []CuptiTimingEvent) []CudaTraceOutput {
	if len(events) == 0 {
		return nil
	}

	var outputs []CudaTraceOutput

	// Fast path: assume all events from same PID (common case)
	pid := libpf.PID(events[0].Pid)
	value, ok := gpuFixers.Load(pid)
	if !ok {
		log.Warnf("no GPU fixer found for PID %d in AddTimes", pid)
		return nil
	}
	fixer := value.(*gpuTraceFixer)

	var otherPID []CuptiTimingEvent
	fixer.mu.Lock()
	for i := range events {
		ev := &events[i]
		if libpf.PID(ev.Pid) != pid {
			otherPID = append(otherPID, *ev)
			continue
		}
		if out, ok := fixer.addTime(ev); ok {
			outputs = append(outputs, out)
		}
	}
	fixer.mu.Unlock()

	// Handle rare events from other PIDs
	for i := range otherPID {
		if out, ok := addTimeSingle(&otherPID[i]); ok {
			outputs = append(outputs, out)
		}
	}

	return outputs
}

// MaybeClearAll periodically clears all fixers and returns metrics for the caller to report.
func MaybeClearAll() []metrics.Metric {
	var totalTimes, totalTraces, totalTimesCleared, totalTracesCleared int

	gpuFixers.Range(func(key, value any) bool {
		fixer := value.(*gpuTraceFixer)
		stats := fixer.maybeClear()
		totalTimes += stats.timesLen
		totalTraces += stats.tracesLen
		totalTimesCleared += stats.timesCleared
		totalTracesCleared += stats.tracesCleared

		return true
	})

	out := []metrics.Metric{
		{ID: metrics.IDCudaTimesAwaitingTraces, Value: metrics.MetricValue(totalTimes)},
		{ID: metrics.IDCudaTracesAwaitingTimes, Value: metrics.MetricValue(totalTraces)},
	}
	if totalTimesCleared > 0 || totalTracesCleared > 0 {
		out = append(out,
			metrics.Metric{ID: metrics.IDCudaTimesCleared, Value: metrics.MetricValue(totalTimesCleared)},
			metrics.Metric{ID: metrics.IDCudaTracesCleared, Value: metrics.MetricValue(totalTracesCleared)},
		)
	}
	return out
}

// Symbolize is a stub — ConvertTrace handles CUDA frames directly via `case libpf.CUDA`,
// so this should never be called in normal operation.
func (i *Instance) Symbolize(f libpf.EbpfFrame, _ *libpf.Frames, _ libpf.FrameMapping) error {
	return fmt.Errorf("CUDA Symbolize called unexpectedly for frame type %d: %w",
		f.Type(), interpreter.ErrMismatchInterpreterType)
}

func (d *data) Unload(ebpf interpreter.EbpfHandler) {
	if d.link != nil {
		log.Debugf("[cuda] parcagpu USDT probes closed for %s", d.path)
		if err := d.link.Unload(); err != nil {
			log.Errorf("error closing cuda usdt link: %s", err)
		}
	}
}
