// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
)

var (
	errSystemAnalysisNotHandled = errors.New("system analysis request was not handled")
	errSystemAnalysisFailed     = errors.New("system analysis helper failed")
)

const systemAnalysisRetryTimeout = 250 * time.Millisecond

// systemAnalysisProgNames maps system analysis work types to program names.
var systemAnalysisProgNames = map[uint32]string{
	support.SysAnalysisReadMem:  "read_kernel_memory",
	support.SysAnalysisReadTask: "read_task_struct",
}

// systemAnalysisProbes runs tid-guarded system analysis requests. Each
// program only services requests carrying its work type, so both probes
// can stay attached at the same time. The links keep the attached
// programs loaded; Close detaches the probes and unloads the programs.
// The caller owns the maps.
type systemAnalysisProbes struct {
	coll           *cebpf.CollectionSpec
	systemAnalysis *cebpf.Map
	links          map[string]link.Link
}

func newSystemAnalysisProbes(coll *cebpf.CollectionSpec, systemAnalysis *cebpf.Map) *systemAnalysisProbes {
	return &systemAnalysisProbes{
		coll:           coll,
		systemAnalysis: systemAnalysis,
		links:          make(map[string]link.Link),
	}
}

// ensureAttached loads and attaches the named analysis program on first use.
func (p *systemAnalysisProbes) ensureAttached(progName string) error {
	if _, ok := p.links[progName]; ok {
		return nil
	}

	progSpec, ok := p.coll.Programs[progName]
	if !ok {
		return fmt.Errorf("program %s does not exist", progName)
	}

	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	prog, err := cebpf.NewProgram(progSpec)
	if err != nil {
		return fmt.Errorf("failed to load %s: %v", progName, err)
	}
	// The link takes a reference on the program, so the descriptor can be
	// released once attached, or right away on failure.
	defer prog.Close()

	var progLink link.Link
	switch prog.Type() {
	case cebpf.RawTracepoint:
		progLink, err = link.AttachRawTracepoint(link.RawTracepointOptions{
			Name:    "sys_enter",
			Program: prog,
		})
	case cebpf.TracePoint:
		progLink, err = link.Tracepoint("syscalls", "sys_enter_bpf", prog, nil)
	default:
		err = fmt.Errorf("invalid system analysis program type '%v'", prog.Type())
	}
	if err != nil {
		return fmt.Errorf("failed to attach %s to tracepoint: %v", progName, err)
	}

	p.links[progName] = progLink
	return nil
}

func (p *systemAnalysisProbes) Close() {
	for name, progLink := range p.links {
		_ = progLink.Close()
		delete(p.links, name)
	}
}

// readKernelCode reads size bytes from the given kernel address.
func (p *systemAnalysisProbes) readKernelCode(address libpf.SymbolValue, size int) ([]byte, error) {
	code, _, err := p.execute(support.SysAnalysisReadMem, address, size)
	if err != nil {
		log.Warnf("Failed to load code: %v.\n"+
			"Possible reasons include using a kernel without syscall tracepoints enabled.", err)
	}
	return code, err
}

// readTaskStruct reads bytes from the given offset of the current task_struct.
func (p *systemAnalysisProbes) readTaskStruct(address libpf.SymbolValue, size int) ([]byte, uint64, error) {
	return p.execute(support.SysAnalysisReadTask, address, size)
}

// execute services a read request via the analysis program of the given
// work type. For read_task_struct, the returned addr is the struct
// pt_regs pointer on the entry stack.
func (p *systemAnalysisProbes) execute(work uint32, address libpf.SymbolValue, size int,
) (code []byte, addr uint64, err error) {
	if p.systemAnalysis == nil {
		return nil, 0, errors.New("system_analysis map is not available")
	}

	progName, ok := systemAnalysisProgNames[work]
	if !ok {
		return nil, 0, fmt.Errorf("invalid system analysis work %d", work)
	}

	// Pin the thread so only its syscalls service the tid-guarded request.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err = p.ensureAttached(progName); err != nil {
		return nil, 0, err
	}

	systemAnalysis := p.systemAnalysis

	maxSize := int(unsafe.Sizeof(support.SystemAnalysis{}.Code))
	if size < 0 || size > maxSize {
		return nil, 0, fmt.Errorf("invalid read size for system_analysis %d", size)
	}
	if size == 0 {
		size = maxSize
	}

	key0 := uint32(0)
	data := support.SystemAnalysis{
		Type:    work,
		Tid:     uint32(unix.Gettid()),
		Size:    uint32(size),
		Address: uint64(address),
	}

	if err = systemAnalysis.Update(unsafe.Pointer(&key0), unsafe.Pointer(&data),
		cebpf.UpdateAny); err != nil {
		return nil, 0, fmt.Errorf("failed to write system_analysis 0x%x: %v",
			address, err)
	}

	// The tracepoint services the request on entry of the next syscall of
	// this thread, which is the lookup below.
	err = systemAnalysis.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&data))
	if err == nil && data.Tid != 0 {
		start := time.Now()
		// Under multi-vCPU QEMU TCG the freshly patched tracepoint can be
		// late to propagate to this vCPU. Keep polling; the request stays
		// armed for this thread.
		for ; time.Since(start) < systemAnalysisRetryTimeout; time.Sleep(5 * time.Millisecond) {
			if err = systemAnalysis.Lookup(unsafe.Pointer(&key0), unsafe.Pointer(&data)); err != nil || data.Tid == 0 {
				break
			}
		}
		log.Infof("System analysis needed retries, waited %v", time.Since(start))
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to get analysis data: %v", err)
	}
	if err = validateSystemAnalysisResult(data, address); err != nil {
		return nil, 0, err
	}

	return data.Code[:size:size], data.Address, nil
}

func validateSystemAnalysisResult(data support.SystemAnalysis, address libpf.SymbolValue) error {
	if data.Tid != 0 {
		return fmt.Errorf("%w for tid %d at 0x%x", errSystemAnalysisNotHandled, data.Tid, address)
	}

	if data.Err != 0 {
		if data.Err < 0 {
			return fmt.Errorf("%w at 0x%x: %w (helper err=%d)", errSystemAnalysisFailed, address, syscall.Errno(-data.Err), data.Err)
		}

		return fmt.Errorf("%w at 0x%x: helper err=%d", errSystemAnalysisFailed, address, data.Err)
	}

	return nil
}
