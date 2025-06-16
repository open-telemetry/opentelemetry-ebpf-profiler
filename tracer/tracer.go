/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package tracer contains functionality for populating tracers.
package tracer

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	lru "github.com/elastic/go-freelru"
	"github.com/elastic/go-perf"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/host"
	hostcpu "github.com/elastic/otel-profiling-agent/hostmetadata/host"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind/localintervalcache"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind/localstackdeltaprovider"
	"github.com/elastic/otel-profiling-agent/libpf/periodiccaller"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/libpf/rlimit"
	"github.com/elastic/otel-profiling-agent/libpf/xsync"
	"github.com/elastic/otel-profiling-agent/metrics"
	"github.com/elastic/otel-profiling-agent/proc"
	pm "github.com/elastic/otel-profiling-agent/processmanager"
	pmebpf "github.com/elastic/otel-profiling-agent/processmanager/ebpf"
	"github.com/elastic/otel-profiling-agent/reporter"
	"github.com/elastic/otel-profiling-agent/support"
	"github.com/elastic/otel-profiling-agent/times"
)

/*
#include <stdint.h>
#include "../support/ebpf/types.h"
*/
import "C"

// Compile time check to make sure config.Times satisfies the interfaces.
var _ Intervals = (*config.Times)(nil)

const (
	// ProbabilisticThresholdMax defines the upper bound of the probabilistic profiling
	// threshold.
	ProbabilisticThresholdMax = 100
)

// Constants that define the status of probabilistic profiling.
const (
	probProfilingEnable  = 1
	probProfilingDisable = -1
)

// Intervals is a subset of config.IntervalsAndTimers.
type Intervals interface {
	MonitorInterval() time.Duration
	TracePollInterval() time.Duration
	PIDCleanupInterval() time.Duration
}

// Tracer provides an interface for loading and initializing the eBPF components as
// well as for monitoring the output maps for new traces and count updates.
type Tracer struct {
	fallbackSymbolHit  atomic.Uint64
	fallbackSymbolMiss atomic.Uint64

	// ebpfMaps holds the currently loaded eBPF maps.
	ebpfMaps map[string]*cebpf.Map
	// ebpfProgs holds the currently loaded eBPF programs.
	ebpfProgs map[string]*cebpf.Program

	// kernelSymbols is used to hold the kernel symbol addresses we are tracking
	kernelSymbols *libpf.SymbolMap

	// kernelModules holds symbols/addresses for the kernel module address space
	kernelModules *libpf.SymbolMap

	// perfEntrypoints holds a list of frequency based perf events that are opened on the system.
	perfEntrypoints xsync.RWMutex[[]*perf.Event]

	// hooks holds references to loaded eBPF hooks.
	hooks map[hookPoint]link.Link

	// processManager keeps track of loading, unloading and organization of information
	// that is required to unwind processes in the kernel. This includes maintaining the
	// associated eBPF maps.
	processManager *pm.ProcessManager

	// transmittedFallbackSymbols keeps track of the already-transmitted fallback symbols.
	// It is not thread-safe: concurrent accesses must be synchronized.
	transmittedFallbackSymbols *lru.LRU[libpf.FrameID, libpf.Void]

	// triggerPIDProcessing is used as manual trigger channel to request immediate
	// processing of pending PIDs. This is requested on notifications from eBPF code
	// when process events take place (new, exit, unknown PC).
	triggerPIDProcessing chan bool

	// pidEvents notifies the tracer of new PID events.
	// It needs to be buffered to avoid locking the writers and stacking up resources when we
	// read new PIDs at startup or notified via eBPF.
	pidEvents chan libpf.PID

	// intervals provides access to globally configured timers and counters.
	intervals Intervals

	hasBatchOperations bool

	// moduleFileIDs maps kernel module names to their respective FileID.
	moduleFileIDs map[string]libpf.FileID

	// reporter allows swapping out the reporter implementation.
	reporter reporter.SymbolReporter
}

// hookPoint specifies the group and name of the hooked point in the kernel.
type hookPoint struct {
	group, name string
}

// processKernelModulesMetadata computes the FileID of kernel files and reports executable metadata
// for all kernel modules and the vmlinux image.
func processKernelModulesMetadata(ctx context.Context,
	rep reporter.SymbolReporter, kernelModules *libpf.SymbolMap) (map[string]libpf.FileID, error) {
	result := make(map[string]libpf.FileID, kernelModules.Len())
	kernelModules.ScanAllNames(func(name libpf.SymbolName) {
		nameStr := string(name)
		if !libpf.IsValidString(nameStr) {
			log.Errorf("Invalid string representation of file name in "+
				"processKernelModulesMetadata: %v", []byte(nameStr))
			return
		}

		// Read the kernel and modules ELF notes from sysfs (works since Linux 2.6.24)
		notesFile := fmt.Sprintf("/sys/module/%s/notes/.note.gnu.build-id", nameStr)

		// The vmlinux notes section is in a different location
		if nameStr == "vmlinux" {
			notesFile = "/sys/kernel/notes"
		}

		buildID, err := pfelf.GetBuildIDFromNotesFile(notesFile)
		var fileID libpf.FileID
		// Require at least 16 bytes of BuildID to ensure there is enough entropy for a FileID.
		// 16 bytes could happen when --build-id=md5 is passed to `ld`. This would imply a custom
		// kernel.
		if err == nil && len(buildID) >= 16 {
			fileID = pfelf.CalculateKernelFileID(buildID)
			result[nameStr] = fileID
			rep.ExecutableMetadata(ctx, fileID, nameStr, buildID)
		} else {
			log.Errorf("Failed to get GNU BuildID for kernel module %s: '%s' (%v)",
				nameStr, buildID, err)
		}
	})

	return result, nil
}

// collectIntervalCacheMetrics starts collecting the metrics of cache every monitorInterval.
func collectIntervalCacheMetrics(ctx context.Context, cache nativeunwind.IntervalCache,
	monitorInterval time.Duration) {
	periodiccaller.Start(ctx, monitorInterval, func() {
		size, err := cache.GetCurrentCacheSize()
		if err != nil {
			log.Errorf("Failed to determine size of cache: %v", err)
			return
		}
		hit, miss := cache.GetAndResetHitMissCounters()

		metrics.AddSlice([]metrics.Metric{
			{
				ID:    metrics.IDLocalIntervalCacheSize,
				Value: metrics.MetricValue(size),
			},
			{
				ID:    metrics.IDLocalIntervalCacheHit,
				Value: metrics.MetricValue(hit),
			},
			{
				ID:    metrics.IDLocalIntervalCacheMiss,
				Value: metrics.MetricValue(miss),
			},
		})
	})
}

// NewTracer loads eBPF code and map definitions from the ELF module at the configured
// path.
func NewTracer(ctx context.Context, rep reporter.SymbolReporter, intervals Intervals,
	includeTracers []bool, filterErrorFrames bool) (*Tracer, error) {
	kernelSymbols, err := proc.GetKallsyms("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel symbols: %v", err)
	}

	// Based on includeTracers we decide later which are loaded into the kernel.
	ebpfMaps, ebpfProgs, err := initializeMapsAndPrograms(includeTracers, kernelSymbols)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF code: %v", err)
	}

	// Create a cache that can be used by the stack delta provider to get
	// cached interval structures.
	// We just started to monitor the size of the interval cache. So it is hard at
	// the moment to define the maximum size of it.
	// Therefore, we will start with a limit of 500 MBytes.
	intervalStructureCache, err := localintervalcache.New(500 * 1024 * 1024)
	if err != nil {
		return nil, fmt.Errorf("failed to create local interval cache: %v", err)
	}
	collectIntervalCacheMetrics(ctx, intervalStructureCache, intervals.MonitorInterval())

	// Create a stack delta provider which is used by the process manager to extract
	// stack deltas from the executables.
	localStackDeltaProvider := localstackdeltaprovider.New(intervalStructureCache)

	ebpfHandler, err := pmebpf.LoadMaps(ebpfMaps)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF maps: %v", err)
	}

	hasBatchOperations := ebpfHandler.SupportsGenericBatchOperations()

	processManager, err := pm.New(ctx, includeTracers, intervals.MonitorInterval(), ebpfHandler,
		nil, rep, localStackDeltaProvider, filterErrorFrames)
	if err != nil {
		return nil, fmt.Errorf("failed to create processManager: %v", err)
	}

	const fallbackSymbolsCacheSize = 16384

	kernelModules, err := proc.GetKernelModules("/proc/modules", kernelSymbols)
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel modules: %v", err)
	}

	transmittedFallbackSymbols, err :=
		lru.New[libpf.FrameID, libpf.Void](fallbackSymbolsCacheSize, libpf.FrameID.Hash32)
	if err != nil {
		return nil, fmt.Errorf("unable to instantiate transmitted fallback symbols cache: %v", err)
	}

	moduleFileIDs, err := processKernelModulesMetadata(ctx, rep, kernelModules)
	if err != nil {
		return nil, fmt.Errorf("failed to extract kernel modules metadata: %v", err)
	}

	perfEventList := []*perf.Event{}

	return &Tracer{
		processManager:             processManager,
		kernelSymbols:              kernelSymbols,
		kernelModules:              kernelModules,
		transmittedFallbackSymbols: transmittedFallbackSymbols,
		triggerPIDProcessing:       make(chan bool, 1),
		pidEvents:                  make(chan libpf.PID, pidEventBufferSize),
		ebpfMaps:                   ebpfMaps,
		ebpfProgs:                  ebpfProgs,
		hooks:                      make(map[hookPoint]link.Link),
		intervals:                  intervals,
		hasBatchOperations:         hasBatchOperations,
		perfEntrypoints:            xsync.NewRWMutex(perfEventList),
		moduleFileIDs:              moduleFileIDs,
		reporter:                   rep,
	}, nil
}

// Close provides functionality for Tracer to perform cleanup tasks.
// NOTE: Close may be called multiple times in succession.
func (t *Tracer) Close() {
	events := t.perfEntrypoints.WLock()
	for _, event := range *events {
		if err := event.Disable(); err != nil {
			log.Errorf("Failed to disable perf event: %v", err)
		}
		if err := event.Close(); err != nil {
			log.Errorf("Failed to close perf event: %v", err)
		}
	}
	*events = nil
	t.perfEntrypoints.WUnlock(&events)

	// Avoid resource leakage by closing all kernel hooks.
	for hookPoint, hook := range t.hooks {
		if err := hook.Close(); err != nil {
			log.Errorf("Failed to close '%s/%s': %v", hookPoint.group, hookPoint.name, err)
		}
		delete(t.hooks, hookPoint)
	}

	t.processManager.Close()
}

func buildStackDeltaTemplates(coll *cebpf.CollectionSpec) error {
	// Prepare the inner map template of the stack deltas map-of-maps.
	// This cannot be provided from the eBPF C code, and needs to be done here.
	for i := support.StackDeltaBucketSmallest; i <= support.StackDeltaBucketLargest; i++ {
		mapName := fmt.Sprintf("exe_id_to_%d_stack_deltas", i)
		def := coll.Maps[mapName]
		if def == nil {
			return fmt.Errorf("ebpf map '%s' not found", mapName)
		}
		def.InnerMap = &cebpf.MapSpec{
			Type:       cebpf.Array,
			KeySize:    uint32(C.sizeof_uint32_t),
			ValueSize:  uint32(C.sizeof_StackDelta),
			MaxEntries: 1 << i,
		}
	}
	return nil
}

// initializeMapsAndPrograms loads the definitions for the eBPF maps and programs provided
// by the embedded elf file and loads these into the kernel.
func initializeMapsAndPrograms(includeTracers []bool, kernelSymbols *libpf.SymbolMap) (
	ebpfMaps map[string]*cebpf.Map, ebpfProgs map[string]*cebpf.Program, err error) {
	// Loading specifications about eBPF programs and maps from the embedded elf file
	// does not load them into the kernel.
	// A collection specification holds the information about eBPF programs and maps.
	// References to eBPF maps in the eBPF programs are just placeholders that need to be
	// replaced by the actual loaded maps later on with RewriteMaps before loading the
	// programs into the kernel.
	coll, err := support.LoadCollectionSpec()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load specification for tracers: %v", err)
	}

	err = buildStackDeltaTemplates(coll)
	if err != nil {
		return nil, nil, err
	}

	ebpfMaps = make(map[string]*cebpf.Map)
	ebpfProgs = make(map[string]*cebpf.Program)

	// Load all maps into the kernel that are used later on in eBPF programs. So we can rewrite
	// in the next step the placesholders in the eBPF programs with the file descriptors of the
	// loaded maps in the kernel.
	if err = loadAllMaps(coll, ebpfMaps); err != nil {
		return nil, nil, fmt.Errorf("failed to load eBPF maps: %v", err)
	}

	// Replace the place holders for map access in the eBPF programs with
	// the file descriptors of the loaded maps.
	// nolint:staticcheck
	if err = coll.RewriteMaps(ebpfMaps); err != nil {
		return nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	if !config.NoKernelVersionCheck() {
		var major, minor, patch uint32
		major, minor, patch, err = GetCurrentKernelVersion()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get kernel version: %v", err)
		}
		if hasProbeReadBug(major, minor, patch) {
			patched := checkForMaccessPatch(coll, ebpfMaps, kernelSymbols)
			if !patched {
				return nil, nil, fmt.Errorf("your kernel version %d.%d.%d is affected by a Linux "+
					"kernel bug that can lead to system freezes, terminating host "+
					"agent now to avoid triggering this bug", major, minor, patch)
			}
		}
	}

	if err = loadUnwinders(coll, ebpfProgs, ebpfMaps["progs"],
		includeTracers); err != nil {
		return nil, nil, fmt.Errorf("failed to load eBPF programs: %v", err)
	}

	if err = loadSystemConfig(coll, ebpfMaps, kernelSymbols, includeTracers); err != nil {
		return nil, nil, fmt.Errorf("failed to load system config: %v", err)
	}

	if err = removeTemporaryMaps(ebpfMaps); err != nil {
		return nil, nil, fmt.Errorf("failed to remove temporary maps: %v", err)
	}

	return ebpfMaps, ebpfProgs, nil
}

// removeTemporaryMaps unloads and deletes eBPF maps that are only required for the
// initialization.
func removeTemporaryMaps(ebpfMaps map[string]*cebpf.Map) error {
	// remove no longer needed eBPF maps
	funcAddressMap := ebpfMaps["codedump_addr"]
	functionCode := ebpfMaps["codedump_code"]
	if err := funcAddressMap.Close(); err != nil {
		log.Errorf("Failed to close codedump_addr: %v", err)
	}
	delete(ebpfMaps, "codedump_addr")
	if err := functionCode.Close(); err != nil {
		log.Errorf("Failed to close codedump_code: %v", err)
	}
	delete(ebpfMaps, "codedump_code")
	return nil
}

// loadAllMaps loads all eBPF maps that are used in our eBPF programs.
func loadAllMaps(coll *cebpf.CollectionSpec, ebpfMaps map[string]*cebpf.Map) error {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	// Redefine the maximum number of map entries for selected eBPF maps.
	adaption := make(map[string]uint32, 4)

	const (
		// The following sizes X are used as 2^X, and determined empirically

		// 1 million executable pages / 4GB of executable address space
		pidPageMappingInfoSize = 20

		stackDeltaPageToInfoSize = 16
		exeIDToStackDeltasSize   = 16
	)

	adaption["pid_page_to_mapping_info"] =
		1 << uint32(pidPageMappingInfoSize+config.MapScaleFactor())
	adaption["stack_delta_page_to_info"] =
		1 << uint32(stackDeltaPageToInfoSize+config.MapScaleFactor())

	for i := support.StackDeltaBucketSmallest; i <= support.StackDeltaBucketLargest; i++ {
		mapName := fmt.Sprintf("exe_id_to_%d_stack_deltas", i)
		adaption[mapName] = 1 << uint32(exeIDToStackDeltasSize+config.MapScaleFactor())
	}

	for mapName, mapSpec := range coll.Maps {
		if newSize, ok := adaption[mapName]; ok {
			log.Debugf("Size of eBPF map %s: %v", mapName, newSize)
			mapSpec.MaxEntries = newSize
		}
		ebpfMap, err := cebpf.NewMap(mapSpec)
		if err != nil {
			return fmt.Errorf("failed to load %s: %v", mapName, err)
		}
		ebpfMaps[mapName] = ebpfMap
	}

	return nil
}

// isProgramEnabled checks if one of the given tracers in enable is set in includeTracers.
func isProgramEnabled(includeTracers []bool, enable []config.TracerType) bool {
	for _, tracer := range enable {
		if includeTracers[tracer] {
			return true
		}
	}
	return false
}

// loadUnwinders just satisfies the proof of concept and loads all eBPF programs
func loadUnwinders(coll *cebpf.CollectionSpec, ebpfProgs map[string]*cebpf.Program,
	tailcallMap *cebpf.Map, includeTracers []bool) error {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	type prog struct {
		// enable is a list of TracerTypes for which this eBPF program should be loaded.
		// Set to `nil` / empty to always load unconditionally.
		enable []config.TracerType
		// name of the eBPF program
		name string
		// progID defines the ID for the eBPF program that is used as key in the tailcallMap.
		progID uint32
		// noTailCallTarget indicates if this eBPF program should be added to the tailcallMap.
		noTailCallTarget bool
	}

	logLevel, logSize := config.BpfVerifierLogSetting()
	programOptions := cebpf.ProgramOptions{
		LogLevel: cebpf.LogLevel(logLevel),
		LogSize:  logSize,
	}

	for _, unwindProg := range []prog{
		{
			progID: uint32(support.ProgUnwindStop),
			name:   "unwind_stop",
		},
		{
			progID: uint32(support.ProgUnwindNative),
			name:   "unwind_native",
		},
		{
			progID: uint32(support.ProgUnwindHotspot),
			name:   "unwind_hotspot",
			enable: []config.TracerType{config.HotspotTracer},
		},
		{
			progID: uint32(support.ProgUnwindPerl),
			name:   "unwind_perl",
			enable: []config.TracerType{config.PerlTracer},
		},
		{
			progID: uint32(support.ProgUnwindPHP),
			name:   "unwind_php",
			enable: []config.TracerType{config.PHPTracer},
		},
		{
			progID: uint32(support.ProgUnwindPython),
			name:   "unwind_python",
			enable: []config.TracerType{config.PythonTracer},
		},
		{
			progID: uint32(support.ProgUnwindRuby),
			name:   "unwind_ruby",
			enable: []config.TracerType{config.RubyTracer},
		},
		{
			progID: uint32(support.ProgUnwindV8),
			name:   "unwind_v8",
			enable: []config.TracerType{config.V8Tracer},
		},
		{
			name:             "tracepoint__sched_process_exit",
			noTailCallTarget: true,
		},
		{
			name:             "native_tracer_entry",
			noTailCallTarget: true,
		},
	} {
		if len(unwindProg.enable) > 0 && !isProgramEnabled(includeTracers, unwindProg.enable) {
			continue
		}

		// Load the eBPF program into the kernel. If no error is returned,
		// the eBPF program can be used/called/triggered from now on.
		unwinder, err := cebpf.NewProgramWithOptions(coll.Programs[unwindProg.name],
			programOptions)
		if err != nil {
			// These errors tend to have hundreds of lines, so we print each line individually.
			scanner := bufio.NewScanner(strings.NewReader(err.Error()))
			for scanner.Scan() {
				log.Error(scanner.Text())
			}
			return fmt.Errorf("failed to load %s", unwindProg.name)
		}

		ebpfProgs[unwindProg.name] = unwinder
		fd := uint32(unwinder.FD())
		if unwindProg.noTailCallTarget {
			continue
		}
		if err := tailcallMap.Update(unsafe.Pointer(&unwindProg.progID), unsafe.Pointer(&fd),
			cebpf.UpdateAny); err != nil {
			// Every eBPF program that is loaded within loadUnwinders can be the
			// destination of a tail call of another eBPF program. If we can not update
			// the eBPF map that manages these destinations our unwinding will fail.
			return fmt.Errorf("failed to update tailcall map: %v", err)
		}
	}

	return nil
}

// List PIDs in /proc and send them in the Tracer channel for reading.
func (t *Tracer) populatePIDs(ctx context.Context) error {
	// Inform the process manager and our backend about the new mappings.
	pids, err := proc.ListPIDs()
	if err != nil {
		return fmt.Errorf("failure reading PID list from /proc: %v", err)
	}
	for _, pid := range pids {
		for {
			select {
			case <-ctx.Done():
				return nil
			case t.pidEvents <- pid:
				goto next_pid
			default:
				// Workaround to implement a non blocking send to a channel.
				// To avoid a busy loop on this non blocking channel send operation
				// time.Sleep() is used.
				time.Sleep(50 * time.Millisecond)
			}
		}
	next_pid:
	}
	return nil
}

// insertKernelFrames fetches the kernel stack frames for a particular kstackID and populates
// the trace with these kernel frames. It also allocates the memory for the frames of the trace.
// It returns the number of kernel frames for kstackID or an error.
func (t *Tracer) insertKernelFrames(trace *host.Trace, ustackLen uint32,
	kstackID int32) (uint32, error) {
	cKstackID := C.s32(kstackID)
	kstackVal := make([]C.uint64_t, support.PerfMaxStackDepth)

	if err := t.ebpfMaps["kernel_stackmap"].Lookup(unsafe.Pointer(&cKstackID),
		unsafe.Pointer(&kstackVal[0])); err != nil {
		return 0, fmt.Errorf("failed to lookup kernel frames for stackID %d: %v", kstackID, err)
	}

	// The kernel returns absolute addresses in kernel address
	// space format. Here just the stack length is needed.
	// But also debug print the symbolization based on kallsyms.
	var kstackLen uint32
	for kstackLen < support.PerfMaxStackDepth && kstackVal[kstackLen] != 0 {
		kstackLen++
	}

	trace.Frames = make([]host.Frame, kstackLen+ustackLen)

	var kernelSymbolCacheHit, kernelSymbolCacheMiss uint64

	for i := uint32(0); i < kstackLen; i++ {
		var fileID libpf.FileID
		// Translate the kernel address into something that can be
		// later symbolized. The address is made relative to
		// matching module's ELF .text section:
		//  - main image should have .text section at start of the code segment
		//  - modules are ELF object files (.o) without program headers and
		//    LOAD segments. the address is relative to the .text section
		mod, addr, _ := t.kernelModules.LookupByAddress(
			libpf.SymbolValue(kstackVal[i]))
		symbol, offs, foundSymbol := t.kernelSymbols.LookupByAddress(
			libpf.SymbolValue(kstackVal[i]))

		fileID, foundFileID := t.moduleFileIDs[string(mod)]

		if !foundFileID {
			fileID = libpf.UnknownKernelFileID
		}

		log.Debugf(" kstack[%d] = %v+%x (%v+%x)", i, string(mod), addr, symbol, offs)

		hostFileID := host.CalculateKernelFileID(fileID)
		t.processManager.FileIDMapper.Set(hostFileID, fileID)

		trace.Frames[i] = host.Frame{
			File:   hostFileID,
			Lineno: libpf.AddressOrLineno(addr),
			Type:   libpf.KernelFrame,
		}

		// Kernel frame PCs need to be adjusted by -1. This duplicates logic done in the trace
		// converter. This should be fixed with PF-1042.
		if foundSymbol && foundFileID {
			t.reportFallbackKernelSymbol(fileID, symbol, trace.Frames[i].Lineno-1,
				&kernelSymbolCacheHit, &kernelSymbolCacheMiss)
		}
	}
	t.fallbackSymbolMiss.Add(kernelSymbolCacheMiss)
	t.fallbackSymbolHit.Add(kernelSymbolCacheHit)

	return kstackLen, nil
}

// reportFallbackKernelSymbol reports fallback symbols for kernel frames, after checking if the
// symbols were previously sent.
func (t *Tracer) reportFallbackKernelSymbol(
	fileID libpf.FileID, symbolName libpf.SymbolName, frameAddress libpf.AddressOrLineno,
	kernelSymbolCacheHit, kernelSymbolCacheMiss *uint64) {
	frameID := libpf.NewFrameID(fileID, frameAddress)

	// Only report it if it's not in our LRU list of transmitted symbols.
	if !t.transmittedFallbackSymbols.Contains(frameID) {
		t.reporter.ReportFallbackSymbol(frameID, string(symbolName))

		// There is no guarantee that the above report will be successfully delivered, but this
		// should be sufficient for the time being. Other machines may succeed, and it's no big deal
		// if we can't deliver 100% of symbols.
		t.transmittedFallbackSymbols.Add(frameID, libpf.Void{})
		(*kernelSymbolCacheMiss)++
		return
	}
	(*kernelSymbolCacheHit)++
}

// enableEvent removes the entry of given eventType from the inhibitEvents map
// so that the eBPF code will send the event again.
func (t *Tracer) enableEvent(eventType int) {
	inhibitEventsMap := t.ebpfMaps["inhibit_events"]

	// The map entry might not exist, so just ignore the potential error.
	et := uint32(eventType)
	_ = inhibitEventsMap.Delete(unsafe.Pointer(&et))
}

// monitorPIDEventsMap periodically iterates over the eBPF map pid_events,
// collects PIDs and writes them to the keys slice.
func (t *Tracer) monitorPIDEventsMap(keys *[]uint32) {
	eventsMap := t.ebpfMaps["pid_events"]
	var key, nextKey uint32
	var value bool
	keyFound := true
	deleteBatch := make(libpf.Set[uint32])

	// Key 0 retrieves the very first element in the hash map as
	// it is guaranteed not to exist in pid_events.
	key = 0
	if err := eventsMap.NextKey(unsafe.Pointer(&key), unsafe.Pointer(&nextKey)); err != nil {
		if errors.Is(err, cebpf.ErrKeyNotExist) {
			log.Debugf("Empty pid_events map")
			return
		}
		log.Fatalf("Failed to read from pid_events map: %v", err)
	}

	for keyFound {
		key = nextKey

		if err := eventsMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			log.Fatalf("Failed to lookup '%v' in pid_events: %v", key, err)
		}

		// Lookup the next map entry before deleting the current one.
		if err := eventsMap.NextKey(unsafe.Pointer(&key), unsafe.Pointer(&nextKey)); err != nil {
			if !errors.Is(err, cebpf.ErrKeyNotExist) {
				log.Fatalf("Failed to read from pid_events map: %v", err)
			}
			keyFound = false
		}

		if !t.hasBatchOperations {
			// Now that we have the next key, we can delete the current one.
			if err := eventsMap.Delete(unsafe.Pointer(&key)); err != nil {
				log.Fatalf("Failed to delete '%v' from pid_events: %v", key, err)
			}
		} else {
			// Store to-be-deleted keys in a map so we can delete them all with a single
			// bpf syscall.
			deleteBatch[key] = libpf.Void{}
		}

		// If we process keys inline with iteration (e.g. by sending them to t.pidEvents at this
		// exact point), we may block sending to the channel, delay the iteration and may introduce
		// race conditions (related to deletion). For that reason, keys are first collected and,
		// after the iteration has finished, sent to the channel.
		*keys = append(*keys, key)
	}

	keysToDelete := len(deleteBatch)
	if keysToDelete != 0 {
		keys := libpf.MapKeysToSlice(deleteBatch)
		if _, err := eventsMap.BatchDelete(keys, nil); err != nil {
			log.Fatalf("Failed to batch delete %d entries from pid_events map: %v",
				keysToDelete, err)
		}
	}
}

// eBPFMetricsCollector retrieves the eBPF metrics, calculates their delta values,
// and translates eBPF IDs into Metric ID.
// Returns a slice of Metric ID/Value pairs.
func (t *Tracer) eBPFMetricsCollector(
	translateIDs []metrics.MetricID,
	previousMetricValue []metrics.MetricValue) []metrics.Metric {
	metricsMap := t.ebpfMaps["metrics"]
	metricsUpdates := make([]metrics.Metric, 0, len(translateIDs))

	// Iterate over all known metric IDs
	for ebpfID, metricID := range translateIDs {
		var perCPUValues []uint64

		// Checking for 'gaps' in the translation table.
		// That allows non-contiguous metric IDs, e.g. after removal/deprecation of a metric ID.
		if metricID == metrics.IDInvalid {
			continue
		}

		eID := uint32(ebpfID)
		if err := metricsMap.Lookup(unsafe.Pointer(&eID), &perCPUValues); err != nil {
			log.Errorf("Failed trying to lookup per CPU element: %v", err)
			continue
		}
		value := metrics.MetricValue(0)
		for _, val := range perCPUValues {
			value += metrics.MetricValue(val)
		}

		// The monitoring infrastructure expects instantaneous values (gauges).
		// => for cumulative metrics (counters), send deltas of the observed values, so they
		// can be interpreted as gauges.
		if ebpfID < support.MetricIDBeginCumulative {
			// We don't assume 64bit counters to overflow
			deltaValue := value - previousMetricValue[ebpfID]

			// 0 deltas add no value when summed up for display purposes in the UI
			if deltaValue == 0 {
				continue
			}

			previousMetricValue[ebpfID] = value
			value = deltaValue
		}

		// Collect the metrics for reporting
		metricsUpdates = append(metricsUpdates, metrics.Metric{
			ID:    metricID,
			Value: value,
		})
	}

	return metricsUpdates
}

// loadBpfTrace parses a raw BPF trace into a `host.Trace` instance.
//
// If the raw trace contains a kernel stack ID, the kernel stack is also
// retrieved and inserted at the appropriate position.
func (t *Tracer) loadBpfTrace(raw []byte) *host.Trace {
	frameListOffs := int(unsafe.Offsetof(C.Trace{}.frames))

	if len(raw) < frameListOffs {
		panic("trace record too small")
	}

	frameSize := int(unsafe.Sizeof(C.Frame{}))
	ptr := (*C.Trace)(unsafe.Pointer(unsafe.SliceData(raw)))

	// NOTE: can't do exact check here: kernel adds a few padding bytes to messages.
	if len(raw) < frameListOffs+int(ptr.stack_len)*frameSize {
		panic("unexpected record size")
	}

	trace := &host.Trace{
		Comm:  C.GoString((*C.char)(unsafe.Pointer(&ptr.comm))),
		PID:   libpf.PID(ptr.pid),
		KTime: times.KTime(ptr.ktime),
	}

	// Trace fields included in the hash:
	//  - PID, kernel stack ID, length & frame array.
	// Intentionally excluded:
	//  - ktime, COMM
	ptr.comm = [16]C.char{}
	ptr.ktime = 0
	trace.Hash = host.TraceHash(xxh3.Hash128(raw).Lo)

	userFrameOffs := 0
	if ptr.kernel_stack_id >= 0 {
		kstackLen, err := t.insertKernelFrames(
			trace, uint32(ptr.stack_len), int32(ptr.kernel_stack_id))

		if err != nil {
			log.Errorf("Failed to get kernel stack frames for 0x%x: %v", trace.Hash, err)
		} else {
			userFrameOffs = int(kstackLen)
		}
	}

	// If there are no kernel frames, or reading them failed, we are responsible
	// for allocating the columnar frame array.
	if len(trace.Frames) == 0 {
		trace.Frames = make([]host.Frame, ptr.stack_len)
	}

	for i := 0; i < int(ptr.stack_len); i++ {
		rawFrame := &ptr.frames[i]
		trace.Frames[userFrameOffs+i] = host.Frame{
			File:   host.FileID(rawFrame.file_id),
			Lineno: libpf.AddressOrLineno(rawFrame.addr_or_line),
			Type:   libpf.FrameType(rawFrame.kind),
		}
	}

	return trace
}

// StartMapMonitors starts goroutines for collecting metrics and monitoring eBPF
// maps for tracepoints, new traces, trace count updates and unknown PCs.
func (t *Tracer) StartMapMonitors(ctx context.Context, traceOutChan chan *host.Trace) error {
	eventMetricCollector := t.startEventMonitor(ctx)

	startPollingPerfEventMonitor(ctx, t.ebpfMaps["trace_events"], t.intervals.TracePollInterval(),
		int(config.SamplesPerSecond())*int(unsafe.Sizeof(C.Trace{})), func(rawTrace []byte) {
			traceOutChan <- t.loadBpfTrace(rawTrace)
		})

	pidEvents := make([]uint32, 0)
	periodiccaller.StartWithManualTrigger(ctx, t.intervals.MonitorInterval(),
		t.triggerPIDProcessing, func(manualTrigger bool) {
			t.enableEvent(support.EventTypeGenericPID)
			t.monitorPIDEventsMap(&pidEvents)

			for _, ev := range pidEvents {
				log.Debugf("=> PID: %v", ev)
				t.pidEvents <- libpf.PID(ev)
			}

			// Keep the underlying array alive to avoid GC pressure
			pidEvents = pidEvents[:0]
		})

	// translateIDs is a translation table for eBPF IDs into Metric IDs.
	// Index is the ebpfID, value is the corresponding metricID.
	// nolint:lll
	translateIDs := []metrics.MetricID{
		C.metricID_UnwindCallInterpreter:                      metrics.IDUnwindCallInterpreter,
		C.metricID_UnwindErrZeroPC:                            metrics.IDUnwindErrZeroPC,
		C.metricID_UnwindErrStackLengthExceeded:               metrics.IDUnwindErrStackLengthExceeded,
		C.metricID_UnwindErrBadTSDAddr:                        metrics.IDUnwindErrBadTLSAddr,
		C.metricID_UnwindErrBadTPBaseAddr:                     metrics.IDUnwindErrBadTPBaseAddr,
		C.metricID_UnwindNativeAttempts:                       metrics.IDUnwindNativeAttempts,
		C.metricID_UnwindNativeFrames:                         metrics.IDUnwindNativeFrames,
		C.metricID_UnwindNativeStackDeltaStop:                 metrics.IDUnwindNativeStackDeltaStop,
		C.metricID_UnwindNativeErrLookupTextSection:           metrics.IDUnwindNativeErrLookupTextSection,
		C.metricID_UnwindNativeErrLookupIterations:            metrics.IDUnwindNativeErrLookupIterations,
		C.metricID_UnwindNativeErrLookupRange:                 metrics.IDUnwindNativeErrLookupRange,
		C.metricID_UnwindNativeErrKernelAddress:               metrics.IDUnwindNativeErrKernelAddress,
		C.metricID_UnwindNativeErrWrongTextSection:            metrics.IDUnwindNativeErrWrongTextSection,
		C.metricID_UnwindNativeErrPCRead:                      metrics.IDUnwindNativeErrPCRead,
		C.metricID_UnwindPythonAttempts:                       metrics.IDUnwindPythonAttempts,
		C.metricID_UnwindPythonFrames:                         metrics.IDUnwindPythonFrames,
		C.metricID_UnwindPythonErrBadPyThreadStateCurrentAddr: metrics.IDUnwindPythonErrBadPyThreadStateCurrentAddr,
		C.metricID_UnwindPythonErrZeroThreadState:             metrics.IDUnwindPythonErrZeroThreadState,
		C.metricID_UnwindPythonErrBadThreadStateFrameAddr:     metrics.IDUnwindPythonErrBadThreadStateFrameAddr,
		C.metricID_UnwindPythonZeroFrameCodeObject:            metrics.IDUnwindPythonZeroFrameCodeObject,
		C.metricID_UnwindPythonErrBadCodeObjectArgCountAddr:   metrics.IDUnwindPythonErrBadCodeObjectArgCountAddr,
		C.metricID_UnwindNativeErrStackDeltaInvalid:           metrics.IDUnwindNativeErrStackDeltaInvalid,
		C.metricID_ErrEmptyStack:                              metrics.IDErrEmptyStack,
		C.metricID_UnwindHotspotAttempts:                      metrics.IDUnwindHotspotAttempts,
		C.metricID_UnwindHotspotFrames:                        metrics.IDUnwindHotspotFrames,
		C.metricID_UnwindHotspotErrNoCodeblob:                 metrics.IDUnwindHotspotErrNoCodeblob,
		C.metricID_UnwindHotspotErrInvalidCodeblob:            metrics.IDUnwindHotspotErrInvalidCodeblob,
		C.metricID_UnwindHotspotErrInterpreterFP:              metrics.IDUnwindHotspotErrInterpreterFP,
		C.metricID_UnwindHotspotErrLrUnwindingMidTrace:        metrics.IDUnwindHotspotErrLrUnwindingMidTrace,
		C.metricID_UnwindHotspotUnsupportedFrameSize:          metrics.IDHotspotUnsupportedFrameSize,
		C.metricID_UnwindNativeSmallPC:                        metrics.IDUnwindNativeSmallPC,
		C.metricID_UnwindNativeErrLookupStackDeltaInnerMap:    metrics.IDUnwindNativeErrLookupStackDeltaInnerMap,
		C.metricID_UnwindNativeErrLookupStackDeltaOuterMap:    metrics.IDUnwindNativeErrLookupStackDeltaOuterMap,
		C.metricID_ErrBPFCurrentComm:                          metrics.IDErrBPFCurrentComm,
		C.metricID_UnwindPHPAttempts:                          metrics.IDUnwindPHPAttempts,
		C.metricID_UnwindPHPFrames:                            metrics.IDUnwindPHPFrames,
		C.metricID_UnwindPHPErrBadCurrentExecuteData:          metrics.IDUnwindPHPErrBadCurrentExecuteData,
		C.metricID_UnwindPHPErrBadZendExecuteData:             metrics.IDUnwindPHPErrBadZendExecuteData,
		C.metricID_UnwindPHPErrBadZendFunction:                metrics.IDUnwindPHPErrBadZendFunction,
		C.metricID_UnwindPHPErrBadZendOpline:                  metrics.IDUnwindPHPErrBadZendOpline,
		C.metricID_UnwindRubyAttempts:                         metrics.IDUnwindRubyAttempts,
		C.metricID_UnwindRubyFrames:                           metrics.IDUnwindRubyFrames,
		C.metricID_UnwindPerlAttempts:                         metrics.IDUnwindPerlAttempts,
		C.metricID_UnwindPerlFrames:                           metrics.IDUnwindPerlFrames,
		C.metricID_UnwindPerlTSD:                              metrics.IDUnwindPerlTLS,
		C.metricID_UnwindPerlReadStackInfo:                    metrics.IDUnwindPerlReadStackInfo,
		C.metricID_UnwindPerlReadContextStackEntry:            metrics.IDUnwindPerlReadContextStackEntry,
		C.metricID_UnwindPerlResolveEGV:                       metrics.IDUnwindPerlResolveEGV,
		C.metricID_UnwindHotspotErrInvalidRA:                  metrics.IDUnwindHotspotErrInvalidRA,
		C.metricID_UnwindV8Attempts:                           metrics.IDUnwindV8Attempts,
		C.metricID_UnwindV8Frames:                             metrics.IDUnwindV8Frames,
		C.metricID_UnwindV8ErrBadFP:                           metrics.IDUnwindV8ErrBadFP,
		C.metricID_UnwindV8ErrBadJSFunc:                       metrics.IDUnwindV8ErrBadJSFunc,
		C.metricID_UnwindV8ErrBadCode:                         metrics.IDUnwindV8ErrBadCode,
		C.metricID_ReportedPIDsErr:                            metrics.IDReportedPIDsErr,
		C.metricID_PIDEventsErr:                               metrics.IDPIDEventsErr,
		C.metricID_UnwindNativeLr0:                            metrics.IDUnwindNativeLr0,
		C.metricID_NumProcNew:                                 metrics.IDNumProcNew,
		C.metricID_NumProcExit:                                metrics.IDNumProcExit,
		C.metricID_NumUnknownPC:                               metrics.IDNumUnknownPC,
		C.metricID_NumGenericPID:                              metrics.IDNumGenericPID,
		C.metricID_UnwindPythonErrBadCFrameFrameAddr:          metrics.IDUnwindPythonErrBadCFrameFrameAddr,
		C.metricID_MaxTailCalls:                               metrics.IDMaxTailCalls,
		C.metricID_UnwindPythonErrNoProcInfo:                  metrics.IDUnwindPythonErrNoProcInfo,
		C.metricID_UnwindPythonErrBadAutoTlsKeyAddr:           metrics.IDUnwindPythonErrBadAutoTlsKeyAddr,
		C.metricID_UnwindPythonErrReadThreadStateAddr:         metrics.IDUnwindPythonErrReadThreadStateAddr,
		C.metricID_UnwindPythonErrReadTsdBase:                 metrics.IDUnwindPythonErrReadTsdBase,
		C.metricID_UnwindRubyErrNoProcInfo:                    metrics.IDUnwindRubyErrNoProcInfo,
		C.metricID_UnwindRubyErrReadStackPtr:                  metrics.IDUnwindRubyErrReadStackPtr,
		C.metricID_UnwindRubyErrReadStackSize:                 metrics.IDUnwindRubyErrReadStackSize,
		C.metricID_UnwindRubyErrReadCfp:                       metrics.IDUnwindRubyErrReadCfp,
		C.metricID_UnwindRubyErrReadEp:                        metrics.IDUnwindRubyErrReadEp,
		C.metricID_UnwindRubyErrReadIseqBody:                  metrics.IDUnwindRubyErrReadIseqBody,
		C.metricID_UnwindRubyErrReadIseqEncoded:               metrics.IDUnwindRubyErrReadIseqEncoded,
		C.metricID_UnwindRubyErrReadIseqSize:                  metrics.IDUnwindRubyErrReadIseqSize,
		C.metricID_UnwindNativeErrLrUnwindingMidTrace:         metrics.IDUnwindNativeErrLrUnwindingMidTrace,
		C.metricID_UnwindNativeErrReadKernelModeRegs:          metrics.IDUnwindNativeErrReadKernelModeRegs,
		C.metricID_UnwindNativeErrChaseIrqStackLink:           metrics.IDUnwindNativeErrChaseIrqStackLink,
		C.metricID_UnwindV8ErrNoProcInfo:                      metrics.IDUnwindV8ErrNoProcInfo,
		C.metricID_UnwindNativeErrBadUnwindInfoIndex:          metrics.IDUnwindNativeErrBadUnwindInfoIndex,
	}

	// previousMetricValue stores the previously retrieved metric values to
	// calculate and store delta values.
	previousMetricValue := make([]metrics.MetricValue, len(translateIDs))

	periodiccaller.Start(ctx, t.intervals.MonitorInterval(), func() {
		metrics.AddSlice(eventMetricCollector())
		metrics.AddSlice(t.eBPFMetricsCollector(translateIDs, previousMetricValue))

		metrics.AddSlice([]metrics.Metric{
			{
				ID:    metrics.IDKernelFallbackSymbolLRUHit,
				Value: metrics.MetricValue(t.fallbackSymbolHit.Swap(0)),
			},
			{
				ID:    metrics.IDKernelFallbackSymbolLRUMiss,
				Value: metrics.MetricValue(t.fallbackSymbolMiss.Swap(0)),
			},
		})
	})

	return nil
}

// AttachTracer attaches the main tracer entry point to the perf interrupt events. The tracer
// entry point is always the native tracer. The native tracer will determine when to invoke the
// interpreter tracers based on address range information.
func (t *Tracer) AttachTracer(sampleFreq int) error {
	tracerProg, ok := t.ebpfProgs["native_tracer_entry"]
	if !ok {
		return fmt.Errorf("entry program is not available")
	}

	perfAttribute := new(perf.Attr)
	perfAttribute.SetSampleFreq(uint64(sampleFreq))
	if err := perf.CPUClock.Configure(perfAttribute); err != nil {
		return fmt.Errorf("failed to configure software perf event: %v", err)
	}

	onlineCPUIDs, err := hostcpu.ParseCPUCoreIDs(hostcpu.CPUOnlinePath)
	if err != nil {
		return fmt.Errorf("failed to get online CPUs: %v", err)
	}

	events := t.perfEntrypoints.WLock()
	defer t.perfEntrypoints.WUnlock(&events)
	for _, id := range onlineCPUIDs {
		perfEvent, err := perf.Open(perfAttribute, perf.AllThreads, id, nil)
		if err != nil {
			return fmt.Errorf("failed to attach to perf event on CPU %d: %v", id, err)
		}
		if err := perfEvent.SetBPF(uint32(tracerProg.FD())); err != nil {
			return fmt.Errorf("failed to attach eBPF program to perf event: %v", err)
		}
		*events = append(*events, perfEvent)
	}
	return nil
}

// EnableProfiling enables the perf interrupt events with the attached eBPF programs.
func (t *Tracer) EnableProfiling() error {
	events := t.perfEntrypoints.WLock()
	defer t.perfEntrypoints.WUnlock(&events)
	if len(*events) == 0 {
		return fmt.Errorf("no perf events available to enable for profiling")
	}
	for id, event := range *events {
		if err := event.Enable(); err != nil {
			return fmt.Errorf("failed to enable perf event on CPU %d: %v", id, err)
		}
	}
	return nil
}

// probabilisticProfile performs a single iteration of probabilistic profiling. It will generate
// a random number between 0 and ProbabilisticThresholdMax-1 every interval. If the random
// number is smaller than threshold it will enable the frequency based sampling for this
// time interval. Otherwise the frequency based sampling events are disabled.
func (t *Tracer) probabilisticProfile(interval time.Duration, threshold uint) {
	enableSampling := false
	var probProfilingStatus = probProfilingDisable

	if rand.Intn(ProbabilisticThresholdMax) < int(threshold) {
		enableSampling = true
		probProfilingStatus = probProfilingEnable
		log.Debugf("Start sampling for next interval (%v)", interval)
	} else {
		log.Debugf("Stop sampling for next interval (%v)", interval)
	}

	events := t.perfEntrypoints.WLock()
	defer t.perfEntrypoints.WUnlock(&events)
	var enableErr, disableErr metrics.MetricValue
	for _, event := range *events {
		if enableSampling {
			if err := event.Enable(); err != nil {
				enableErr++
				log.Errorf("Failed to enable frequency based sampling: %v",
					err)
			}
			continue
		}
		if err := event.Disable(); err != nil {
			disableErr++
			log.Errorf("Failed to disable frequency based sampling: %v", err)
		}
	}
	if enableErr != 0 {
		metrics.Add(metrics.IDPerfEventEnableErr, enableErr)
	}
	if disableErr != 0 {
		metrics.Add(metrics.IDPerfEventDisableErr, disableErr)
	}
	metrics.Add(metrics.IDProbProfilingStatus,
		metrics.MetricValue(probProfilingStatus))
}

// StartProbabilisticProfiling periodically runs probabilistic profiling.
func (t *Tracer) StartProbabilisticProfiling(ctx context.Context,
	interval time.Duration, threshold uint) {
	metrics.Add(metrics.IDProbProfilingInterval,
		metrics.MetricValue(interval.Seconds()))

	// Run a single iteration of probabilistic profiling to avoid needing
	// to wait for the first interval to pass with periodiccaller.Start()
	// before getting called.
	t.probabilisticProfile(interval, threshold)

	periodiccaller.Start(ctx, interval, func() {
		t.probabilisticProfile(interval, threshold)
	})
}

func (t *Tracer) ConvertTrace(trace *host.Trace) *libpf.Trace {
	return t.processManager.ConvertTrace(trace)
}

func (t *Tracer) SymbolizationComplete(traceCaptureKTime times.KTime) {
	t.processManager.SymbolizationComplete(traceCaptureKTime)
}
