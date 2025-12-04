package tracer

import (
	"errors"
	"fmt"
	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/process"
	"github.com/toliu/opentelemetry-ebpf-profiler/processmanager"
	"golang.org/x/exp/maps"
	"runtime"
	"slices"
	"unsafe"
)

// #include "../support/ebpf/types.h"
import "C"

type uprobe struct {
	exec                *link.Executable
	symbol              string
	progEnter, progExit string
	canFail             bool
	pid                 int
	opts                *link.UprobeOptions
}

// loadUProbeUnwinders reuses large parts of loadPerfUnwinders. By default all eBPF programs
// are written as perf event eBPF programs. loadUProbeUnwinders dynamically rewrites the
// specification of these programs to kprobe eBPF programs and adjusts tail call maps.
func loadUProbeUnwinders(coll *cebpf.CollectionSpec, ebpfProgs map[string]*cebpf.Program,
	tailcallMap *cebpf.Map, progs []progLoaderHelper,
	bpfVerifierLogLevel uint32, perfTailCallMapFD int) error {
	programOptions := cebpf.ProgramOptions{
		LogLevel: cebpf.LogLevel(bpfVerifierLogLevel),
	}
	for _, unwindProg := range progs {
		if !unwindProg.enable {
			continue
		}

		unwindProgName := unwindProg.name
		if !unwindProg.noTailCallTarget {
			unwindProgName = "kprobe_" + unwindProg.name
		}

		progSpec, ok := coll.Programs[unwindProgName]
		if !ok {
			return fmt.Errorf("program %s does not exist", unwindProgName)
		}

		// Replace the prog array for the tail calls.
		insns := progArrayReferences(perfTailCallMapFD, progSpec.Instructions)
		for _, ins := range insns {
			if err := progSpec.Instructions[ins].AssociateMap(tailcallMap); err != nil {
				return fmt.Errorf("failed to rewrite map ptr: %v", err)
			}
		}

		if err := loadProgram(ebpfProgs, tailcallMap, unwindProg.progID, progSpec,
			programOptions, unwindProg.noTailCallTarget); err != nil {
			return err
		}
	}
	return nil
}

func (t *Tracer) AttachUProbes(u *uprobe) error {
	if enter, ok := t.ebpfProgs[u.progEnter]; ok {
		if uprobeLink, err := u.exec.Uprobe(u.symbol, enter, u.opts); err != nil {
			if u.canFail {
				err = nil
			}
			err = fmt.Errorf("failed to attach u-probe program %s: %v", u.progEnter, err)
			return err
		} else {
			t.memProfileHooks[libpf.PID(u.pid)] = append(t.memProfileHooks[libpf.PID(u.pid)], uprobeLink)
		}
	}
	if exit, ok := t.ebpfProgs[u.progExit]; ok {
		if uRetProbeLink, err := u.exec.Uretprobe(u.symbol, exit, u.opts); err != nil {
			if u.canFail {
				err = nil
			}
			err = fmt.Errorf("failed to attach u-probe program %s: %v", u.progExit, err)
			return err
		} else {
			t.memProfileHooks[libpf.PID(u.pid)] = append(t.memProfileHooks[libpf.PID(u.pid)], uRetProbeLink)
		}
	}
	log.Debugf("attached u-probe program %v", u)
	return nil
}

func (t *Tracer) detachMemProfile(pid libpf.PID) {
	if links, ok := t.memProfileHooks[pid]; ok {
		for _, _link := range links {
			if e := _link.Close(); e != nil {
				log.Errorf("failed to close memprofile link{ pid:%d, link:%v, err: %v", pid, _link, e)
			}
		}
	}
	log.Infof("detachMemProfile for pid %v", pid)
	delete(t.memProfileHooks, pid)
}

// StartCLikeMemProfiling starts mem profiling for c/c++/rust by attaching the programs to the hooks.
func (t *Tracer) StartCLikeMemProfiling(exec *link.Executable, _ *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) error {
	var errs []error
	for _, u := range []*uprobe{
		{exec, "malloc", "malloc_enter", "malloc_exit", false, pid, opts},
		{exec, "calloc", "calloc_enter", "calloc_exit", false, pid, opts},
		{exec, "realloc", "realloc_enter", "realloc_exit", false, pid, opts},
		{exec, "mmap", "mmap_enter", "mmap_exit", true, pid, opts},
		{exec, "posix_memalign", "posix_memalign_enter", "posix_memalign_exit", false, pid, opts},
		{exec, "valloc", "valloc_enter", "valloc_exit", true, pid, opts},
		{exec, "memalign", "memalign_enter", "memalign_exit", false, pid, opts},
		{exec, "pvalloc", "pvalloc_enter", "pvalloc_exit", true, pid, opts},
		{exec, "aligned_alloc", "aligned_alloc_enter", "aligned_alloc_exit", true, pid, opts},
		{exec, "free", "free_enter", "", false, pid, opts},
		{exec, "munmap", "munmap_enter", "", true, pid, opts},
	} {
		if err := t.AttachUProbes(u); err != nil {
			log.Errorf("failed to attach uprobe:%v, err:%v", u, err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// StartGolangMemProfiling starts mem profiling for golang by attaching the programs to the hooks.
func (t *Tracer) StartGolangMemProfiling(exec *link.Executable, info *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) error {
	prog := "mallocgc_register_enter"
	if (runtime.GOARCH == "amd64" && info.MinorVersion < 17) ||
		(runtime.GOARCH == "arm64" && info.MinorVersion < 18) {
		prog = "mallocgc_stack_enter"
	}
	u := &uprobe{exec, "runtime.mallocgc", prog, "", false, pid, opts}
	err := t.AttachUProbes(u)
	if err != nil {
		log.Errorf("failed to attach uprobe:%v, err:%v", u, err)
	}
	return err
}

// StartPythonMemProfiling starts mem profiling for python by attaching the programs to the hooks.
func (t *Tracer) StartPythonMemProfiling(exec *link.Executable, _ *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) error {
	var errs []error
	for _, u := range []*uprobe{
		{exec, "PyObject_Malloc", "PyObject_Malloc_enter", "PyObject_Malloc_exit", false, pid, opts},
		{exec, "PyObject_Calloc", "PyObject_Calloc_enter", "PyObject_Calloc_exit", false, pid, opts},
		{exec, "PyObject_Realloc", "PyObject_Realloc_enter", "PyObject_Realloc_exit", false, pid, opts},
		{exec, "PyObject_Free", "PyObject_Free_enter", "", false, pid, opts},
	} {
		if err := t.AttachUProbes(u); err != nil {
			log.Errorf("failed to attach uprobe:%v, err:%v", u, err)
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (t *Tracer) TriggerMemProfile(p process.Process) error {
	if memProfileInfo := t.processManager.GetMemProfileInfo(p.PID()); memProfileInfo != nil {
		var startProfiling func(exec *link.Executable, info *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) error
		var exec *link.Executable
		var execPath string
		switch memProfileInfo.Lang {
		case libpf.HotSpot:
		case libpf.Python:
			startProfiling = t.StartPythonMemProfiling
			execPath = memProfileInfo.ExecAbsPath
		case libpf.Golang:
			startProfiling = t.StartGolangMemProfiling
			execPath = memProfileInfo.ExecAbsPath
		default:
			startProfiling = t.StartCLikeMemProfiling
			execPath = memProfileInfo.LibcPath
		}
		if execPath == "" {
			return fmt.Errorf("unable to start memprofiling with empty executeable path: %v", memProfileInfo)
		}
		exec, err := link.OpenExecutable(execPath)
		if err != nil {
			return err
		}
		var opts *link.UprobeOptions
		if p.PID() > 0 {
			opts = &link.UprobeOptions{PID: int(p.PID())}
		}
		return startProfiling(exec, memProfileInfo, int(p.PID()), opts)
	}
	return fmt.Errorf("unable to start memprofile with pid: %d, can not find MemProfile MetaInfo", p.PID())
}

func (t *Tracer) SyncMemProfile(pids []libpf.PID, memProfileBlock uint64) {
	if err := t.SyncMemProfileBlock(memProfileBlock); err != nil {
		return
	}
	oldPids := maps.Keys(t.memProfileHooks)
	var removePids []libpf.PID
	for _, oldP := range oldPids {
		if slices.Contains(pids, oldP) {
			continue
		}
		t.detachMemProfile(oldP)
		removePids = append(removePids, oldP)
	}
	for _, pid := range removePids {
		delete(t.memProfileHooks, pid)
	}
	for _, p := range pids {
		if _, exist := t.memProfileHooks[p]; exist {
			continue
		}
		proc := process.New(p)
		t.processManager.SynchronizeProcess(proc)
		if err := t.TriggerMemProfile(proc); err != nil {
			t.detachMemProfile(proc.PID())
		}
	}
}

func (t *Tracer) SyncMemProfileTargetPids(targetPids []libpf.PID) error {
	return t.processManager.SyncTargetPids(targetPids)
}

func (t *Tracer) SyncMemProfileBlock(block uint64) error {
	if t.memProfileBlock == block {
		return nil
	}
	t.memProfileBlock = block
	// 复用SystemConfig传递内存采样上报的阈值
	syscfg := C.SystemConfig{
		inverse_pac_mask: C.u64(block),
	}
	keyMemConfig := uint32(1)
	err := t.ebpfMaps["system_config"].Update(unsafe.Pointer(&keyMemConfig), unsafe.Pointer(&syscfg),
		cebpf.UpdateAny)
	if err != nil {
		log.Errorf("config memprofile block failed: %v", err)
		return err
	}
	return nil
}
