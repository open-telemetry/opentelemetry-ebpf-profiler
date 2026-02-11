package gpu // import "go.opentelemetry.io/ebpf-profiler/interpreter/gpu"

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"sync"
	"unsafe"

	"github.com/ianlancetaylor/demangle"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
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

// gpuTraceFixer matches traces with timing information for a specific PID.
// We use a single fixer per PID because CUDA correlation IDs are unique per process
// across all devices and streams.
// See: https://docs.nvidia.com/cupti/api/structCUpti__ActivityKernel.html
// The correlationId field: "Each function invocation is assigned a unique correlation ID
// that is identical to the correlation ID in the driver or runtime API activity record
// that launched the kernel."
type gpuTraceFixer struct {
	mu                  sync.Mutex
	timesAwaitingTraces map[uint32][]CuptiTimingEvent // keyed by correlation ID
	tracesAwaitingTimes map[uint32]*libpf.EbpfTrace   // keyed by correlation ID
	maxCorrelationId    uint32                        // track highest ID for threshold-based clearing
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
		tracesAwaitingTimes: make(map[uint32]*libpf.EbpfTrace),
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

// addTrace is called when a CUDA trace is received, to match it with timing info.
// Sends completed traces directly to the output channel (may be multiple for graph launches).
func (f *gpuTraceFixer) addTrace(trace *libpf.EbpfTrace, traceOutChan chan<- *libpf.EbpfTrace) error {
	if len(trace.FrameData) != 0 {
		return errors.New("no frames in trace")
	}
	frame := libpf.EbpfFrame(trace.FrameData)
	if frame.Type() != libpf.CUDAKernelFrame {
		return errors.New("first frame is not a CUDA kernel frame")
	}
	if frame.NumVariables() < 1 {
		return errors.New("CUDA kernel frame is too small")
	}
	cudaId := frame.Variable(0)

	correlationId := uint32(cudaId)
	cbid := int32(cudaId >> 32)

	log.Debugf("[cuda] adding trace with id %d cbid %d (0x%x) for pid %d", correlationId, int(cbid), uint32(cbid), trace.PID)
	f.mu.Lock()
	defer f.mu.Unlock()

	// Update max, detecting wrap-around (new ID much smaller than max means wrap)
	if correlationId > f.maxCorrelationId || f.maxCorrelationId-correlationId > 1<<31 {
		f.maxCorrelationId = correlationId
	}

	evs, ok := f.timesAwaitingTraces[correlationId]
	if ok && len(evs) > 0 {
		// Process any timing events that arrived before this trace
		for idx := range evs {
			log.Debugf("[cuda] gpu trace completed id %d cbid %d (0x%x) for pid %d",
				correlationId, int(cbid), uint32(cbid), trace.PID)
			traceOutChan <- f.prepTrace(trace, &evs[idx])
		}
		// Always delete the key to avoid nil entries accumulating
		delete(f.timesAwaitingTraces, correlationId)
		// For non-graph launches, we've matched the only timing event, done
		if !isGraphLaunch(cbid) {
			return nil
		}
	}
	// Store trace for future timing events
	f.tracesAwaitingTimes[correlationId] = trace
	return nil
}

// addTime is called when timing info is received from eBPF, to match it with a trace.
// Caller must hold f.mu.
func (f *gpuTraceFixer) addTime(ev *CuptiTimingEvent) *libpf.EbpfTrace {
	// Update max, detecting wrap-around (new ID much smaller than max means wrap)
	if ev.Id > f.maxCorrelationId || f.maxCorrelationId-ev.Id > 1<<31 {
		f.maxCorrelationId = ev.Id
	}

	trace, ok := f.tracesAwaitingTimes[ev.Id]
	if ok {
		if ev.Graph == 0 {
			delete(f.tracesAwaitingTimes, ev.Id)
		}
		return f.prepTrace(trace, ev)
	}
	f.timesAwaitingTraces[ev.Id] = append(f.timesAwaitingTraces[ev.Id], *ev)
	return nil
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

// prepTrace prepares a trace with timing information and kernel name.
func (f *gpuTraceFixer) prepTrace(tr *libpf.EbpfTrace, ev *CuptiTimingEvent) *libpf.EbpfTrace {
	if ev.Graph != 0 {
		// Graphs can have many kernels with same correlation ID
		clone := *tr
		tr = &clone
	}
	tr.OffTime = int64(ev.End - ev.Start)
	if tr.CustomLabels == nil {
		tr.CustomLabels = make(map[libpf.String]libpf.String)
	}

	tr.CustomLabels[cudaDevice] = libpf.Intern(strconv.FormatUint(uint64(ev.Dev), 10))
	if ev.Stream != 0 {
		tr.CustomLabels[cudaStream] = libpf.Intern(strconv.FormatUint(uint64(ev.Stream), 10))
	}
	if ev.Graph != 0 {
		tr.CustomLabels[cudaGraph] = libpf.Intern(strconv.FormatUint(uint64(ev.Graph), 10))
		tr.CustomLabels[cudaId] = libpf.Intern(strconv.FormatUint(uint64(ev.Id), 10))
	}
	if len(ev.KernelName) > 0 {
		// Store the raw (mangled) kernel name - demangling happens in Symbolize
		// Use unsafe.String to avoid allocation - Intern/unique.Make will copy if new
		nameBytes := ev.KernelName[:]
		if idx := bytes.IndexByte(nameBytes, 0); idx >= 0 {
			nameBytes = nameBytes[:idx]
		}
		istr := libpf.Intern(unsafe.String(unsafe.SliceData(nameBytes), len(nameBytes)))
		// See collect_trace where we always make the first frame a CUDA kernel frame.
		frame := libpf.EbpfFrame(tr.FrameData)
		if len(frame) == 0 || frame.Type() != libpf.CUDAKernelFrame {
			panic("first frame is not a CUDA kernel frame")
		}
		if frame.NumVariables() < 2 {
			panic("CUDA kernel frame is not long enough")
		}
		frame.SetVariable(1, *(*uint64)(unsafe.Pointer(&istr)))
	}
	return tr
}

// AddTrace is a static function that delegates to the appropriate fixer for the PID.
// Completed traces are sent directly to traceOutChan.
func AddTrace(trace *libpf.EbpfTrace, traceOutChan chan<- *libpf.EbpfTrace) error {
	pid := trace.PID
	value, ok := gpuFixers.Load(pid)
	if !ok {
		return fmt.Errorf("no GPU fixer found for PID %d", pid)
	}
	fixer := value.(*gpuTraceFixer)
	return fixer.addTrace(trace, traceOutChan)
}

// AddTime is a static function that delegates to the appropriate fixer for the PID.
func AddTime(ev *CuptiTimingEvent) *libpf.EbpfTrace {
	pid := libpf.PID(ev.Pid)
	value, ok := gpuFixers.Load(pid)
	if !ok {
		log.Warnf("no GPU fixer found for PID %d", pid)
		return nil
	}
	fixer := value.(*gpuTraceFixer)
	fixer.mu.Lock()
	defer fixer.mu.Unlock()
	return fixer.addTime(ev)
}

// AddTimes processes a batch of timing events, taking the lock once per PID.
func AddTimes(events []CuptiTimingEvent, out chan<- *libpf.EbpfTrace) {
	if len(events) == 0 {
		return
	}

	// Fast path: assume all events from same PID (common case)
	pid := libpf.PID(events[0].Pid)
	value, ok := gpuFixers.Load(pid)
	if !ok {
		return
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
		if trace := fixer.addTime(ev); trace != nil {
			out <- trace
		}
	}
	fixer.mu.Unlock()

	// Handle rare events from other PIDs
	for i := range otherPID {
		if trace := AddTime(&otherPID[i]); trace != nil {
			out <- trace
		}
	}
}

// MaybeClearAll periodically clears all fixers and reports aggregated metrics.
func MaybeClearAll() {
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

	// Report metrics outside of any locks
	metrics.Add(metrics.IDCudaTimesAwaitingTraces, metrics.MetricValue(totalTimes))
	metrics.Add(metrics.IDCudaTracesAwaitingTimes, metrics.MetricValue(totalTraces))
	if totalTimesCleared > 0 || totalTracesCleared > 0 {
		metrics.Add(metrics.IDCudaTimesCleared, metrics.MetricValue(totalTimesCleared))
		metrics.Add(metrics.IDCudaTracesCleared, metrics.MetricValue(totalTracesCleared))
	}
}

func (i *Instance) Symbolize(f libpf.EbpfFrame, frames *libpf.Frames, fm libpf.FrameMapping) error {
	if f.Type() != libpf.CUDAKernelFrame {
		return interpreter.ErrMismatchInterpreterType
	}
	if f.NumVariables() < 2 {
		return errors.New("CUDA frame too small")
	}
	kernelStrAddr := f.Variable(1)
	mangledStr := *(*libpf.String)(unsafe.Pointer(&kernelStrAddr))
	cudaId := f.Variable(0)

	// Demangle the kernel name
	funcName := mangledStr
	if demStr, err := demangle.ToString(
		mangledStr.String(), demangle.NoParams, demangle.NoEnclosingParams); err == nil {
		funcName = libpf.Intern(demStr)
	}

	frames.Append(&libpf.Frame{
		Type:            libpf.CUDAKernelFrame,
		AddressOrLineno: libpf.AddressOrLineno(cudaId),
		FunctionName:    funcName,
	})
	return nil
}

func (d *data) Unload(ebpf interpreter.EbpfHandler) {
	if d.link != nil {
		log.Debugf("[cuda] parcagpu USDT probes closed for %s", d.path)
		if err := d.link.Unload(); err != nil {
			log.Errorf("error closing cuda usdt link: %s", err)
		}
	}
}
