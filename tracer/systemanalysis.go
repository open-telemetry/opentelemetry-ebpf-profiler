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

// systemAnalysisProbes runs tid-guarded system analysis requests. Both
// handlers service the same request slot, so only one program may be
// attached at a time; switching closes the previous attachment. Programs
// are loaded once per kind. Close releases the programs; the caller owns
// the maps.
type systemAnalysisProbes struct {
	coll           *cebpf.CollectionSpec
	systemAnalysis *cebpf.Map
	progs          map[string]*cebpf.Program
	activeName     string
	activeLink     link.Link
}

func newSystemAnalysisProbes(coll *cebpf.CollectionSpec, systemAnalysis *cebpf.Map) *systemAnalysisProbes {
	return &systemAnalysisProbes{
		coll:           coll,
		systemAnalysis: systemAnalysis,
		progs:          make(map[string]*cebpf.Program),
	}
}

// attachProgram attaches the named analysis program, replacing the previous
// attachment: a second live handler would hijack requests meant for the
// other program, as both guard the shared slot by tid only.
func (p *systemAnalysisProbes) attachProgram(progName string) error {
	if p.activeName == progName {
		return nil
	}
	if p.activeLink != nil {
		_ = p.activeLink.Close()
		p.activeLink = nil
		p.activeName = ""
	}

	prog, ok := p.progs[progName]
	if !ok {
		progSpec, ok := p.coll.Programs[progName]
		if !ok {
			return fmt.Errorf("program %s does not exist", progName)
		}

		restoreRlimit, err := rlimit.MaximizeMemlock()
		if err != nil {
			return fmt.Errorf("failed to adjust rlimit: %v", err)
		}
		defer restoreRlimit()

		prog, err = cebpf.NewProgram(progSpec)
		if err != nil {
			return fmt.Errorf("failed to load %s: %v", progName, err)
		}
		p.progs[progName] = prog
	}

	var progLink link.Link
	var err error
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

	p.activeName = progName
	p.activeLink = progLink
	return nil
}

func (p *systemAnalysisProbes) Close() {
	if p.activeLink != nil {
		_ = p.activeLink.Close()
		p.activeLink = nil
		p.activeName = ""
	}
	for name, prog := range p.progs {
		_ = prog.Close()
		delete(p.progs, name)
	}
}

// readKernelCode reads size bytes from the given kernel address.
func (p *systemAnalysisProbes) readKernelCode(address libpf.SymbolValue, size int) ([]byte, error) {
	code, _, err := p.execute("read_kernel_memory", address, size)
	if err != nil {
		log.Warnf("Failed to load code: %v.\n"+
			"Possible reasons include using a kernel without syscall tracepoints enabled.", err)
	}
	return code, err
}

// readTaskStruct reads bytes from the given offset of the current task_struct.
func (p *systemAnalysisProbes) readTaskStruct(address libpf.SymbolValue, size int) ([]byte, uint64, error) {
	return p.execute("read_task_struct", address, size)
}

// execute services a read request via the named analysis program.
// For read_task_struct, the returned addr is the struct pt_regs pointer on
// the entry stack.
func (p *systemAnalysisProbes) execute(progName string, address libpf.SymbolValue, size int,
) (code []byte, addr uint64, err error) {
	if p.systemAnalysis == nil {
		return nil, 0, errors.New("system_analysis map is not available")
	}

	// Pin the thread so only its syscalls service the tid-guarded request.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if err = p.attachProgram(progName); err != nil {
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
		Address: uint64(address),
		Size:    uint32(size),
		Tid:     uint32(unix.Gettid()),
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
