package tracer

import (
	"fmt"
	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/process"
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

func (t *Tracer) AttachUProbes(u *uprobe) {
	if enter, ok := t.ebpfProgs[u.progEnter]; ok {
		if uprobeLink, err := u.exec.Uprobe(u.symbol, enter, u.opts); err != nil {
			if u.canFail {
				err = nil
				return
			}
			log.Errorf("failed to attach u-probe program %s, %s: %v", u.progEnter, u.progExit, err)
			return
		} else {
			t.memProfileHooks[libpf.PID(u.pid)] = append(t.memProfileHooks[libpf.PID(u.pid)], uprobeLink)
		}
	}
	if exit, ok := t.ebpfProgs[u.progExit]; ok {
		if uRetProbeLink, err := u.exec.Uretprobe(u.symbol, exit, u.opts); err != nil {
			if u.canFail {
				err = nil
				return
			}
			log.Errorf("failed to attach u-probe program %s, %s: %v", u.progEnter, u.progExit, err)
			return
		} else {
			t.memProfileHooks[libpf.PID(u.pid)] = append(t.memProfileHooks[libpf.PID(u.pid)], uRetProbeLink)
		}
	}
}

func (t *Tracer) detachMemProfile(pid libpf.PID) {
	if links, ok := t.memProfileHooks[pid]; ok {
		for _, link := range links {
			if e := link.Close(); e != nil {
				log.Errorf("failed to close memprofile link{ pid:%d, link:%v, err: %v", pid, link, e)
			}
		}
	}
	delete(t.memProfileHooks, pid)
}

// StartCLikeMemProfiling starts mem profiling for c/c++/rust by attaching the programs to the hooks.
func (t *Tracer) StartCLikeMemProfiling(execute string, pid int) bool {
	if execute == "" {
		return false
	}
	exec, err := link.OpenExecutable(execute)
	if err != nil {
		return false
	}
	var opts *link.UprobeOptions
	if pid > 0 {
		opts = &link.UprobeOptions{PID: pid}
	}
	for _, u := range []*uprobe{
		{exec, "malloc", "malloc_enter", "malloc_exit", false, pid, opts},
		{exec, "calloc", "calloc_enter", "calloc_exit", false, pid, opts},
		{exec, "realloc", "realloc_enter", "realloc_exit", false, pid, opts},
		{exec, "free", "free_enter", "free_exit", false, pid, opts},
		{exec, "mmap", "mmap_enter", "mmap_exit", true, pid, opts},
		{exec, "posix_memalign", "posix_memalign_enter", "posix_memalign_exit", false, pid, opts},
		{exec, "valloc", "valloc_enter", "valloc_exit", true, pid, opts},
		{exec, "memalign", "memalign_enter", "memalign_exit", false, pid, opts},
		{exec, "pvalloc", "pvalloc_enter", "pvalloc_exit", true, pid, opts},
		{exec, "aligned_alloc", "aligned_alloc_enter", "aligned_alloc_exit", true, pid, opts},
		{exec, "free", "free_enter", "", false, pid, opts},
		{exec, "munmap", "munmap_enter", "", true, pid, opts},
	} {
		t.AttachUProbes(u)
	}
	return true
}

// StartGolangMemProfiling starts mem profiling for golang by attaching the programs to the hooks.
func (t *Tracer) StartGolangMemProfiling(execute string, pid int, isRegister bool) bool {
	if execute == "" {
		return false
	}
	exec, err := link.OpenExecutable(execute)
	if err != nil {
		return false
	}
	var opts *link.UprobeOptions
	if pid > 0 {
		opts = &link.UprobeOptions{PID: pid}
	}
	prog := "mallocgc_register_enter"
	if !isRegister {
		prog = "mallocgc_stack_enter"
	}
	u := &uprobe{exec, "runtime.mallocgc", prog, "", false, pid, opts}
	t.AttachUProbes(u)
	return true
}

func (t *Tracer) TriggerMemProfile(p process.Process) {
	if memProfileInfo := t.processManager.GetMemProfileInfo(p.PID()); memProfileInfo != nil {
		switch memProfileInfo.Lang {
		case libpf.HotSpot:
		case libpf.Python:
		case libpf.Golang:
			isRegister := true
			switch runtime.GOARCH {
			case "amd64":
				if memProfileInfo.MinorVersion < 17 {
					isRegister = false
				}
			case "arm64":
				if memProfileInfo.MinorVersion < 18 {
					isRegister = false
				}
			}
			t.StartGolangMemProfiling(memProfileInfo.ExecAbsPath, int(p.PID()), isRegister)
		default:
			t.StartCLikeMemProfiling(memProfileInfo.LibcPath, int(p.PID()))
		}
		return
	}
	return
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
		t.TriggerMemProfile(proc)
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
