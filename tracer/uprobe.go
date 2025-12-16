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
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/hotspotmem"
	"golang.org/x/exp/maps"
	"runtime"
	"slices"
	"strconv"
	"strings"
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

func (t *Tracer) AttachUProbes(u *uprobe) ([]*link.Link, error) {
	var resLinks []*link.Link
	if enter, ok := t.ebpfProgs[u.progEnter]; ok {
		if uprobeLink, err := u.exec.Uprobe(u.symbol, enter, u.opts); err != nil {
			if u.canFail {
				err = nil
			}
			err = fmt.Errorf("failed to attach u-probe program %s: %v", u.progEnter, err)
			return nil, err
		} else {
			resLinks = append(resLinks, &uprobeLink)
		}
	}
	if exit, ok := t.ebpfProgs[u.progExit]; ok {
		if uRetProbeLink, err := u.exec.Uretprobe(u.symbol, exit, u.opts); err != nil {
			if u.canFail {
				err = nil
			}
			err = fmt.Errorf("failed to attach u-probe program %s: %v", u.progExit, err)
			return nil, err
		} else {
			resLinks = append(resLinks, &uRetProbeLink)
		}
	}
	log.Tracef("attached u-probe program %v", u)
	return resLinks, nil
}

func (t *Tracer) detachMemProfile(pid libpf.PID) {
	memProfileHooks := t.memProfileHooks.WLock()
	if links, ok := (*memProfileHooks)[pid]; ok {
		for _, _link := range links {
			if e := (*_link).Close(); e != nil {
				log.Debugf("failed to close memprofile link{ pid:%d, link:%v, err: %v", pid, _link, e)
			}
		}
	}
	delete(*memProfileHooks, pid)
	t.memProfileHooks.WUnlock(&memProfileHooks)
	if r, ok := t.reporter.(reporter.HotspotMemReporter); ok {
		r.StopHotspotMemProfiling(int(pid))
	}
	log.Tracef("detachMemProfile for pid %v", pid)
}

// StartCLikeMemProfiling starts mem profiling for c/c++/rust by attaching the programs to the hooks.
func (t *Tracer) StartCLikeMemProfiling(exec *link.Executable, _ *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) ([]*link.Link, error) {
	var errs []error
	var links []*link.Link
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
		if ls, err := t.AttachUProbes(u); err != nil {
			log.Debugf("failed to attach uprobe:%v, err:%v", u, err)
			errs = append(errs, err)
		} else {
			links = append(links, ls...)
		}
	}
	return links, errors.Join(errs...)
}

// StartGolangMemProfiling starts mem profiling for golang by attaching the programs to the hooks.
func (t *Tracer) StartGolangMemProfiling(exec *link.Executable, info *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) ([]*link.Link, error) {
	prog := "mallocgc_register_enter"
	if (runtime.GOARCH == "amd64" && info.MinorVersion < 17) ||
		(runtime.GOARCH == "arm64" && info.MinorVersion < 18) {
		prog = "mallocgc_stack_enter"
	}
	u := &uprobe{exec, "runtime.mallocgc", prog, "", false, pid, opts}
	links, err := t.AttachUProbes(u)
	if err != nil {
		log.Debugf("failed to attach uprobe:%v, err:%v", u, err)
	}
	return links, err
}

// StartPythonMemProfiling starts mem profiling for python by attaching the programs to the hooks.
func (t *Tracer) StartPythonMemProfiling(exec *link.Executable, _ *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) ([]*link.Link, error) {
	var errs []error
	var links []*link.Link
	for _, u := range []*uprobe{
		{exec, "PyObject_Malloc", "PyObject_Malloc_enter", "PyObject_Malloc_exit", false, pid, opts},
		{exec, "PyObject_Calloc", "PyObject_Calloc_enter", "PyObject_Calloc_exit", false, pid, opts},
		{exec, "PyObject_Realloc", "PyObject_Realloc_enter", "PyObject_Realloc_exit", false, pid, opts},
		{exec, "PyObject_Free", "PyObject_Free_enter", "", false, pid, opts},
	} {
		if ls, err := t.AttachUProbes(u); err != nil {
			log.Debugf("failed to attach uprobe:%v, err:%v", u, err)
			errs = append(errs, err)
		} else {
			links = append(links, ls...)
		}
	}
	return links, errors.Join(errs...)
}

func (t *Tracer) TriggerMemProfile(p process.Process) error {
	if memProfileInfo := t.processManager.GetMemProfileInfo(p.PID()); memProfileInfo != nil {
		var startProfiling func(exec *link.Executable, info *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) ([]*link.Link, error)
		var exec *link.Executable
		var execPath string
		switch memProfileInfo.Lang {
		case libpf.HotSpot:
			cfg := &hotspotmem.OTLPProfilerConfig{
				PID:           int(p.PID()),
				AllocInterval: t.memProfileBlock, //bytes
			}
			err := t.startHotspotMemProfiling(memProfileInfo, cfg)
			if err != nil {
				t.detachMemProfile(p.PID())
				return err
			}
			memProfileHooks := t.memProfileHooks.WLock()
			(*memProfileHooks)[p.PID()] = nil
			t.memProfileHooks.WUnlock(&memProfileHooks)
			return nil
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
			return fmt.Errorf("unable to start memprofiling for process %d with empty executeable path: %v", p.PID(), memProfileInfo)
		}
		exec, err := link.OpenExecutable(execPath)
		if err != nil {
			return err
		}
		var opts *link.UprobeOptions
		if p.PID() > 0 {
			opts = &link.UprobeOptions{PID: int(p.PID())}
		}
		links, err := startProfiling(exec, memProfileInfo, int(p.PID()), opts)
		memProfileHooks := t.memProfileHooks.WLock()
		(*memProfileHooks)[p.PID()] = links
		t.memProfileHooks.WUnlock(&memProfileHooks)
		return err
	}
	return fmt.Errorf("unable to start memprofile with pid: %d, can not find MemProfile MetaInfo", p.PID())
}

func (t *Tracer) SyncMemProfile(pids map[libpf.PID]struct{}, memProfileBlock uint64) {
	if err := t.SyncMemProfileBlock(memProfileBlock); err != nil {
		return
	}
	if r, ok := t.reporter.(reporter.MemReporter); ok {
		r.SyncTargetPids(pids)
	}
	memProfileHooks := t.memProfileHooks.WLock()
	oldPids := maps.Keys(*memProfileHooks)
	t.memProfileHooks.WUnlock(&memProfileHooks)
	var addProcs []process.Process
	for p, _ := range pids {
		if slices.Contains(oldPids, p) || p == 0 {
			continue
		}
		proc := process.New(p)
		t.processManager.SynchronizeProcess(proc)
		addProcs = append(addProcs, proc)
	}
	var removePids []libpf.PID
	for _, oldP := range oldPids {
		if _, ok := pids[oldP]; ok {
			continue
		}
		removePids = append(removePids, oldP)
	}
	for _, pid := range removePids {
		t.detachMemProfile(pid)
	}
	for _, proc := range addProcs {
		if err := t.TriggerMemProfile(proc); err != nil {
			log.Debugf("failed to trigger memprofile for process %d: %v", proc.PID(), err)
		}
	}
}

func (t *Tracer) SyncMemProfileTargetPids(targetPids map[libpf.PID]struct{}) error {
	t.SyncMemProfile(targetPids, t.memProfileBlock)
	return nil
}

func (t *Tracer) SyncMemProfileBlock(block uint64) error {
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

func (t *Tracer) startHotspotMemProfiling(meta *processmanager.MemProfileMeta, cfg *hotspotmem.OTLPProfilerConfig) error {
	if meta.MajorVersion == 0 {
		lanVerStr := fmt.Sprintf("%s", meta.ItData)
		if lanV := strings.Split(lanVerStr, " "); len(lanV) > 1 {
			for _, s := range lanV[1:] {
				if ver := strings.Split(s, "."); len(ver) > 1 {
					meta.MajorVersion, _ = strconv.Atoi(ver[0])
					meta.MinorVersion, _ = strconv.Atoi(ver[1])
					break
				}
			}
		}
	}
	// 需要java 11及以上才支持
	if meta.MajorVersion < 1 && meta.MinorVersion < 11 {
		return fmt.Errorf("unsupported hotspot-memprofile version: jdk-%d.%d", meta.MajorVersion, meta.MinorVersion)
	}

	if r, ok := t.reporter.(reporter.HotspotMemReporter); ok {
		err := r.StartHotspotMemProfiling(cfg)
		if err != nil {
			return err
		}
	}
	return nil
}
