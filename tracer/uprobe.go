package tracer

import (
	"debug/buildinfo"
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"

	"github.com/toliu/opentelemetry-ebpf-profiler/libpf"
	"github.com/toliu/opentelemetry-ebpf-profiler/process"
	"github.com/toliu/opentelemetry-ebpf-profiler/processmanager"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter"
	"github.com/toliu/opentelemetry-ebpf-profiler/reporter/hotspotmem"
)

// #include "../support/ebpf/types.h"
import "C"

const (
	goVersionPrefix = "Go cmd/compile"
)

var ErrVersionNotFound = errors.New("version info not found")

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

		// uprobe ebpf程序不需要绑定内核结构体或方法，此处强制把此字段置为空
		// 后续需要注意：uprobe的ebpf程序将默认有section为'uprobe/'和'uretprobe/'的约定
		if strings.HasPrefix(progSpec.SectionName, "uprobe/") ||
			strings.HasPrefix(progSpec.SectionName, "uretprobe/") {
			progSpec.AttachTo = ""
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
				return nil, nil
			}
			return nil, fmt.Errorf("failed to attach u-probe program %s: %v", u.progEnter, err)
		} else {
			resLinks = append(resLinks, &uprobeLink)
		}
	}
	if exit, ok := t.ebpfProgs[u.progExit]; ok {
		if uRetProbeLink, err := u.exec.Uretprobe(u.symbol, exit, u.opts); err != nil {
			if u.canFail {
				return nil, nil
			}
			return nil, fmt.Errorf("failed to attach u-probe program %s: %v", u.progExit, err)
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
		/* pvalloc在arm64上不存在,不需要挂载 */
		{exec, "pvalloc", "pvalloc_enter", "pvalloc_exit", true, pid, opts},
		{exec, "aligned_alloc", "aligned_alloc_enter", "aligned_alloc_exit", true, pid, opts},
		{exec, "free", "free_enter", "", false, pid, opts},
		{exec, "munmap", "munmap_enter", "", true, pid, opts},
	} {
		if ls, err := t.AttachUProbes(u); err != nil {
			log.Debugf("failed to attach uprobe:%v, err:%v", u, err)
			errs = append(errs, err)
		} else {
			log.Infof("c-like mem profiling attach uprobe on pid(%d) func(%s)", pid, u.symbol)
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
	} else {
		log.Infof("golang mem profiling attach uprobe on pid(%d) func(%s) on prog(%s)", pid, u.symbol, prog)
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
			log.Infof("python mem profiling attach uprobe on pid(%d) func(%s)", pid, u.symbol)
			links = append(links, ls...)
		}
	}
	return links, errors.Join(errs...)
}

func (t *Tracer) hasMemProfileHooks(pid libpf.PID) bool {
	memProfileHooks := t.memProfileHooks.RLock()
	_, exist := (*memProfileHooks)[pid]
	t.memProfileHooks.RUnlock(&memProfileHooks)
	return exist
}

func (t *Tracer) updateMemProfileHooks(pid libpf.PID, links []*link.Link) {
	memProfileHooks := t.memProfileHooks.WLock()
	(*memProfileHooks)[pid] = links
	t.memProfileHooks.WUnlock(&memProfileHooks)
}

func (t *Tracer) triggerMemProfile(p process.Process) error {
	pid := p.PID()
	if t.hasMemProfileHooks(pid) {
		return nil
	}
	memProfileInfo := t.processManager.GetMemProfileInfo(pid)
	if memProfileInfo == nil {
		return fmt.Errorf("unable to start memprofile with pid: %d, can not find MemProfile MetaInfo", pid)
	}
	var startProfiling func(exec *link.Executable, info *processmanager.MemProfileMeta, pid int, opts *link.UprobeOptions) ([]*link.Link, error)
	var exec *link.Executable
	var execPath string
	switch memProfileInfo.Lang {
	case libpf.HotSpot:
		cfg := &hotspotmem.OTLPProfilerConfig{
			PID:           int(pid),
			AllocInterval: t.memProfileBlock.Load(), //bytes
		}
		err := t.startHotspotMemProfiling(memProfileInfo, cfg)
		if err != nil {
			t.detachMemProfile(pid)
			return err
		}
		t.updateMemProfileHooks(pid, nil)
		return nil
	case libpf.Python:
		startProfiling = t.StartPythonMemProfiling
		execPath = memProfileInfo.LibPythonPath
	case libpf.Golang:
		startProfiling = t.StartGolangMemProfiling
		execPath = memProfileInfo.ExecAbsPath
		if memProfileInfo.MajorVersion == 0 {
			newMemProfileInfo := *memProfileInfo
			// golang在没有栈回溯的时候，也不包含版本信息，需要先解析出go的版本信息
			bi, e := buildinfo.ReadFile(execPath)
			if e != nil {
				return fmt.Errorf("[mem profile] failed to read buildinfo for %s pid(%d): %v", execPath, pid, e)
			}
			major, minor, err := parseGoVersion(bi.GoVersion)
			if err != nil {
				return err
			}
			newMemProfileInfo.MajorVersion = major
			newMemProfileInfo.MinorVersion = minor
			memProfileInfo = &newMemProfileInfo
		}
	case libpf.PHP, libpf.PHPJIT, libpf.Kernel, libpf.Ruby, libpf.Perl, libpf.V8, libpf.Dotnet:
		return nil
	default:
		startProfiling = t.StartCLikeMemProfiling
		execPath = memProfileInfo.LibcPath
	}
	if execPath == "" {
		return fmt.Errorf("unable to start memprofiling for process %d with empty executeable path: %v", pid, memProfileInfo)
	}
	exec, err := link.OpenExecutable(execPath)
	if err != nil {
		return err
	}
	var opts *link.UprobeOptions
	if pid > 0 {
		opts = &link.UprobeOptions{PID: int(pid)}
	}
	links, err := startProfiling(exec, memProfileInfo, int(pid), opts)
	if err != nil {
		return err
	}
	t.updateMemProfileHooks(pid, links)
	return nil
}

func (t *Tracer) monitorMemProfilePids(keys *[]uint32) {
	if t.memProfileBlock.Load() == 0 {
		return
	}

	pids := t.memProfileTargetPids.RLock()
	defer t.memProfileTargetPids.RUnlock(&pids)

	var memProfileTargetPids []libpf.PID
	for pid, add := range *pids {
		if pid == 0 {
			continue
		}
		if add {
			memProfileTargetPids = append(memProfileTargetPids, pid)
			if t.hasMemProfileHooks(pid) {
				continue
			}
			*keys = append(*keys, pid.Hash32())
			if err := t.triggerMemProfile(process.New(pid)); err != nil {
				log.Debugf("failed to trigger memprofile for process %v: %v", pid, err)
			}
		} else {
			t.detachMemProfile(pid)
		}
	}
	log.Debugf("apply mem profiling target pids: %v", memProfileTargetPids)
}

func (t *Tracer) SyncMemProfileBlock(block uint64) error {
	t.memProfileBlock.Store(block)
	// 复用SystemConfig传递内存采样上报的阈值
	syscfg := C.SystemConfig{
		mem_profile_threshold: C.u64(block),
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

func parseGoVersion(r string) (int, int, error) {
	ver := strings.TrimPrefix(r, goVersionPrefix)

	if strings.HasPrefix(ver, "go") {
		v := strings.SplitN(ver[2:], ".", 3)
		var major, minor int
		var err error

		major, err = strconv.Atoi(v[0])
		if err != nil {
			return 0, 0, err
		}

		if len(v) >= 2 {
			minor, err = strconv.Atoi(v[1])
			if err != nil {
				return 0, 0, err
			}
		}
		return major, minor, nil
	}
	return 0, 0, ErrVersionNotFound
}
