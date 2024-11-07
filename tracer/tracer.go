// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package tracer contains functionality for populating tracers.
package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"math/rand/v2"
	"sort"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/elastic/go-perf"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/periodiccaller"
	"go.opentelemetry.io/ebpf-profiler/proc"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"
	"go.opentelemetry.io/ebpf-profiler/util"
)

/*
#include <stdint.h>
#include "../support/ebpf/types.h"
*/
import "C"

// Compile time check to make sure config.Times satisfies the interfaces.
var _ Intervals = (*times.Times)(nil)

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

	// samplesPerSecond holds the configured number of samples per second.
	samplesPerSecond int

	// probabilisticInterval is the time interval for which probabilistic profiling will be enabled.
	probabilisticInterval time.Duration

	// probabilisticThreshold holds the threshold for probabilistic profiling.
	probabilisticThreshold uint
}

type Config struct {
	// Reporter allows swapping out the reporter implementation.
	Reporter reporter.SymbolReporter
	// Intervals provides access to globally configured timers and counters.
	Intervals Intervals
	// IncludeTracers holds information about which tracers are enabled.
	IncludeTracers types.IncludedTracers
	// SamplesPerSecond holds the number of samples per second.
	SamplesPerSecond int
	// MapScaleFactor is the scaling factor for eBPF map sizes.
	MapScaleFactor int
	// FilterErrorFrames indicates whether error frames should be filtered.
	FilterErrorFrames bool
	// KernelVersionCheck indicates whether the kernel version should be checked.
	KernelVersionCheck bool
	// DebugTracer indicates whether to load the debug version of eBPF tracers.
	DebugTracer bool
	// BPFVerifierLogLevel is the log level of the eBPF verifier output.
	BPFVerifierLogLevel uint32
	// ProbabilisticInterval is the time interval for which probabilistic profiling will be enabled.
	ProbabilisticInterval time.Duration
	// ProbabilisticThreshold is the threshold for probabilistic profiling.
	ProbabilisticThreshold uint
	// CollectCustomLabels determines whether to collect custom labels in
	// languages that support them.
	CollectCustomLabels bool
}

// hookPoint specifies the group and name of the hooked point in the kernel.
type hookPoint struct {
	group, name string
}

// processKernelModulesMetadata computes the FileID of kernel files and reports executable metadata
// for all kernel modules and the vmlinux image.
func processKernelModulesMetadata(rep reporter.SymbolReporter, kernelModules *libpf.SymbolMap,
	kernelSymbols *libpf.SymbolMap) (map[string]libpf.FileID, error) {
	result := make(map[string]libpf.FileID, kernelModules.Len())
	kernelModules.VisitAll(func(moduleSym libpf.Symbol) {
		nameStr := string(moduleSym.Name)
		if !util.IsValidString(nameStr) {
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
			fileID = libpf.FileIDFromKernelBuildID(buildID)
		} else {
			fileID = calcFallbackModuleID(moduleSym, kernelSymbols)
			buildID = ""
		}

		result[nameStr] = fileID
		rep.ExecutableMetadata(&reporter.ExecutableMetadataArgs{
			FileID:            fileID,
			FileName:          nameStr,
			GnuBuildID:        buildID,
			DebuglinkFileName: "",
			Interp:            libpf.Kernel,
		})
	})

	return result, nil
}

// calcFallbackModuleID computes a fallback file ID for kernel modules that do not
// have a GNU build ID. Getting the actual file for the kernel module isn't always
// possible since they don't necessarily reside on disk, e.g. when modules are loaded
// from the initramfs that is later unmounted again.
//
// This fallback checksum locates all symbols exported by a given driver, normalizes
// them to offsets and hashes over that. Additionally, the module's name and size are
// hashed as well. This isn't perfect, and we can't do any server-side symbolization
// with these IDs, but at least it provides a stable unique key for the kernel fallback
// symbols that we send.
func calcFallbackModuleID(moduleSym libpf.Symbol, kernelSymbols *libpf.SymbolMap) libpf.FileID {
	modStart := moduleSym.Address
	modEnd := moduleSym.Address + libpf.SymbolValue(moduleSym.Size)

	// Collect symbols belonging to this module + track minimum address.
	var moduleSymbols []libpf.Symbol
	minAddr := libpf.SymbolValue(math.MaxUint64)
	kernelSymbols.VisitAll(func(symbol libpf.Symbol) {
		if symbol.Address >= modStart && symbol.Address < modEnd {
			moduleSymbols = append(moduleSymbols, symbol)
			minAddr = min(minAddr, symbol.Address)
		}
	})

	// Ensure consistent order.
	sort.Slice(moduleSymbols, func(a, b int) bool {
		return moduleSymbols[a].Address < moduleSymbols[b].Address
	})

	// Hash exports and their normalized addresses.
	h := fnv.New128a()
	h.Write([]byte(moduleSym.Name))
	h.Write(libpf.SliceFrom(&moduleSym.Size))

	for _, sym := range moduleSymbols {
		sym.Address -= minAddr // KASLR normalization

		h.Write([]byte(sym.Name))
		h.Write(libpf.SliceFrom(&sym.Address))
	}

	var hash [16]byte
	fileID, err := libpf.FileIDFromBytes(h.Sum(hash[:0]))
	if err != nil {
		panic("calcFallbackModuleID file ID construction is broken")
	}

	log.Debugf("Fallback module ID for module %s is '%s' (min addr: 0x%08X, num exports: %d)",
		moduleSym.Name, fileID.Base64(), minAddr, len(moduleSymbols))

	return fileID
}

// NewTracer loads eBPF code and map definitions from the ELF module at the configured path.
func NewTracer(ctx context.Context, cfg *Config) (*Tracer, error) {
	kernelSymbols, err := proc.GetKallsyms("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel symbols: %v", err)
	}

	// Based on includeTracers we decide later which are loaded into the kernel.
	ebpfMaps, ebpfProgs, err := initializeMapsAndPrograms(cfg.IncludeTracers, kernelSymbols,
		cfg.FilterErrorFrames, cfg.MapScaleFactor, cfg.KernelVersionCheck, cfg.DebugTracer,
		cfg.BPFVerifierLogLevel)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF code: %v", err)
	}

	ebpfHandler, err := pmebpf.LoadMaps(ctx, ebpfMaps)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF maps: %v", err)
	}

	hasBatchOperations := ebpfHandler.SupportsGenericBatchOperations()

	processManager, err := pm.New(ctx, cfg.IncludeTracers, cfg.Intervals.MonitorInterval(),
		ebpfHandler, nil, cfg.Reporter, elfunwindinfo.NewStackDeltaProvider(),
		cfg.FilterErrorFrames, cfg.CollectCustomLabels)
	if err != nil {
		return nil, fmt.Errorf("failed to create processManager: %v", err)
	}

	const fallbackSymbolsCacheSize = 16384

	kernelModules, err := proc.GetKernelModules("/proc/modules", kernelSymbols)
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel modules: %v", err)
	}

	moduleFileIDs, err := processKernelModulesMetadata(cfg.Reporter, kernelModules, kernelSymbols)
	if err != nil {
		return nil, fmt.Errorf("failed to extract kernel modules metadata: %v", err)
	}

	perfEventList := []*perf.Event{}

	return &Tracer{
		processManager:         processManager,
		kernelSymbols:          kernelSymbols,
		kernelModules:          kernelModules,
		triggerPIDProcessing:   make(chan bool, 1),
		pidEvents:              make(chan libpf.PID, pidEventBufferSize),
		ebpfMaps:               ebpfMaps,
		ebpfProgs:              ebpfProgs,
		hooks:                  make(map[hookPoint]link.Link),
		intervals:              cfg.Intervals,
		hasBatchOperations:     hasBatchOperations,
		perfEntrypoints:        xsync.NewRWMutex(perfEventList),
		moduleFileIDs:          moduleFileIDs,
		reporter:               cfg.Reporter,
		samplesPerSecond:       cfg.SamplesPerSecond,
		probabilisticInterval:  cfg.ProbabilisticInterval,
		probabilisticThreshold: cfg.ProbabilisticThreshold,
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
func initializeMapsAndPrograms(includeTracers types.IncludedTracers,
	kernelSymbols *libpf.SymbolMap, filterErrorFrames bool, mapScaleFactor int,
	kernelVersionCheck bool, debugTracer bool, bpfVerifierLogLevel uint32) (
	ebpfMaps map[string]*cebpf.Map, ebpfProgs map[string]*cebpf.Program, err error) {
	// Loading specifications about eBPF programs and maps from the embedded elf file
	// does not load them into the kernel.
	// A collection specification holds the information about eBPF programs and maps.
	// References to eBPF maps in the eBPF programs are just placeholders that need to be
	// replaced by the actual loaded maps later on with RewriteMaps before loading the
	// programs into the kernel.
	coll, err := support.LoadCollectionSpec(debugTracer)
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
	if err = loadAllMaps(coll, ebpfMaps, mapScaleFactor); err != nil {
		return nil, nil, fmt.Errorf("failed to load eBPF maps: %v", err)
	}

	// Replace the place holders for map access in the eBPF programs with
	// the file descriptors of the loaded maps.
	//nolint:staticcheck
	if err = coll.RewriteMaps(ebpfMaps); err != nil {
		return nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	if kernelVersionCheck {
		var major, minor, patch uint32
		major, minor, patch, err = GetCurrentKernelVersion()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get kernel version: %v", err)
		}
		if hasProbeReadBug(major, minor, patch) {
			if err = checkForMaccessPatch(coll, ebpfMaps, kernelSymbols); err != nil {
				return nil, nil, fmt.Errorf("your kernel version %d.%d.%d may be "+
					"affected by a Linux kernel bug that can lead to system "+
					"freezes, terminating host agent now to avoid "+
					"triggering this bug.\n"+
					"If you are certain your kernel is not affected, "+
					"you can override this check at your own risk "+
					"with -no-kernel-version-check.\n"+
					"Error: %v", major, minor, patch, err)
			}
		}
	}

	if err = loadUnwinders(coll, ebpfProgs, ebpfMaps["progs"], includeTracers,
		bpfVerifierLogLevel); err != nil {
		return nil, nil, fmt.Errorf("failed to load eBPF programs: %v", err)
	}

	if err = loadSystemConfig(coll, ebpfMaps, kernelSymbols, includeTracers,
		filterErrorFrames); err != nil {
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
	for _, mapName := range []string{"system_analysis"} {
		if err := ebpfMaps[mapName].Close(); err != nil {
			log.Errorf("Failed to close %s: %v", mapName, err)
			return err
		}
		delete(ebpfMaps, mapName)
	}
	return nil
}

// loadAllMaps loads all eBPF maps that are used in our eBPF programs.
func loadAllMaps(coll *cebpf.CollectionSpec, ebpfMaps map[string]*cebpf.Map,
	mapScaleFactor int) error {
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
		1 << uint32(pidPageMappingInfoSize+mapScaleFactor)
	adaption["stack_delta_page_to_info"] =
		1 << uint32(stackDeltaPageToInfoSize+mapScaleFactor)

	for i := support.StackDeltaBucketSmallest; i <= support.StackDeltaBucketLargest; i++ {
		mapName := fmt.Sprintf("exe_id_to_%d_stack_deltas", i)
		adaption[mapName] = 1 << uint32(exeIDToStackDeltasSize+mapScaleFactor)
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

// loadUnwinders just satisfies the proof of concept and loads all eBPF programs
func loadUnwinders(coll *cebpf.CollectionSpec, ebpfProgs map[string]*cebpf.Program,
	tailcallMap *cebpf.Map, includeTracers types.IncludedTracers,
	bpfVerifierLogLevel uint32) error {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	if err != nil {
		return fmt.Errorf("failed to adjust rlimit: %v", err)
	}
	defer restoreRlimit()

	type prog struct {
		// enable tells whether a prog shall be loaded.
		enable bool
		// name of the eBPF program
		name string
		// progID defines the ID for the eBPF program that is used as key in the tailcallMap.
		progID uint32
		// noTailCallTarget indicates if this eBPF program should be added to the tailcallMap.
		noTailCallTarget bool
	}

	programOptions := cebpf.ProgramOptions{
		LogLevel: cebpf.LogLevel(bpfVerifierLogLevel),
	}

	for _, unwindProg := range []prog{
		{
			progID: uint32(support.ProgUnwindStop),
			name:   "unwind_stop",
			enable: true,
		},
		{
			progID: uint32(support.ProgUnwindNative),
			name:   "unwind_native",
			enable: true,
		},
		{
			progID: uint32(support.ProgUnwindHotspot),
			name:   "unwind_hotspot",
			enable: includeTracers.Has(types.HotspotTracer),
		},
		{
			progID: uint32(support.ProgUnwindPerl),
			name:   "unwind_perl",
			enable: includeTracers.Has(types.PerlTracer),
		},
		{
			progID: uint32(support.ProgUnwindPHP),
			name:   "unwind_php",
			enable: includeTracers.Has(types.PHPTracer),
		},
		{
			progID: uint32(support.ProgUnwindPython),
			name:   "unwind_python",
			enable: includeTracers.Has(types.PythonTracer),
		},
		{
			progID: uint32(support.ProgUnwindRuby),
			name:   "unwind_ruby",
			enable: includeTracers.Has(types.RubyTracer),
		},
		{
			progID: uint32(support.ProgUnwindV8),
			name:   "unwind_v8",
			enable: includeTracers.Has(types.V8Tracer),
		},
		{
			progID: uint32(support.ProgUnwindDotnet),
			name:   "unwind_dotnet",
			enable: includeTracers.Has(types.DotnetTracer),
		},
		{
			name:             "tracepoint__sched_process_exit",
			noTailCallTarget: true,
			enable:           true,
		},
		{
			name:             "native_tracer_entry",
			noTailCallTarget: true,
			enable:           true,
		},
		{
			progID: uint32(support.ProgUnwindLuaJIT),
			name:   "unwind_luajit",
			enable: includeTracers.Has(types.LuaJITTracer),
		},
	} {
		if !unwindProg.enable {
			continue
		}

		// Load the eBPF program into the kernel. If no error is returned,
		// the eBPF program can be used/called/triggered from now on.
		unwinder, err := cebpf.NewProgramWithOptions(coll.Programs[unwindProg.name],
			programOptions)
		if err != nil {
			// These errors tend to have hundreds of lines (or more),
			// so we print each line individually.
			if ve, ok := err.(*cebpf.VerifierError); ok {
				for _, line := range ve.Log {
					log.Error(line)
				}
			} else {
				scanner := bufio.NewScanner(strings.NewReader(err.Error()))
				for scanner.Scan() {
					log.Error(scanner.Text())
				}
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
		// Translate the kernel address into something that can be
		// later symbolized. The address is made relative to
		// matching module's ELF .text section:
		//  - main image should have .text section at start of the code segment
		//  - modules are ELF object files (.o) without program headers and
		//    LOAD segments. the address is relative to the .text section
		mod, addr, _ := t.kernelModules.LookupByAddress(
			libpf.SymbolValue(kstackVal[i]))

		fileID, foundFileID := t.moduleFileIDs[string(mod)]

		if !foundFileID {
			fileID = libpf.UnknownKernelFileID
		}

		hostFileID := host.FileIDFromLibpf(fileID)
		t.processManager.FileIDMapper.Set(hostFileID, fileID)

		trace.Frames[i] = host.Frame{
			File:   hostFileID,
			Lineno: libpf.AddressOrLineno(addr),
			Type:   libpf.KernelFrame,

			// For all kernel frames, the kernel unwinder will always produce a
			// frame in which the RIP is after a call instruction (it hides the
			// top frames that leads to the unwinder itself).
			ReturnAddress: true,
		}

		if !foundFileID {
			continue
		}

		// Kernel frame PCs need to be adjusted by -1. This duplicates logic done in the trace
		// converter. This should be fixed with PF-1042.
		frameID := libpf.NewFrameID(fileID, trace.Frames[i].Lineno-1)
		if t.reporter.FrameKnown(frameID) {
			kernelSymbolCacheHit++
			continue
		}
		kernelSymbolCacheMiss++

		if symbol, _, foundSymbol := t.kernelSymbols.LookupByAddress(
			libpf.SymbolValue(kstackVal[i])); foundSymbol {
			t.reporter.FrameMetadata(&reporter.FrameMetadataArgs{
				FrameID:      frameID,
				FunctionName: string(symbol),
			})
		}
	}

	t.fallbackSymbolMiss.Add(kernelSymbolCacheMiss)
	t.fallbackSymbolHit.Add(kernelSymbolCacheHit)

	return kstackLen, nil
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
		Comm:             C.GoString((*C.char)(unsafe.Pointer(&ptr.comm))),
		APMTraceID:       *(*libpf.APMTraceID)(unsafe.Pointer(&ptr.apm_trace_id)),
		APMTransactionID: *(*libpf.APMTransactionID)(unsafe.Pointer(&ptr.apm_transaction_id)),
		PID:              libpf.PID(ptr.pid),
		TID:              libpf.PID(ptr.tid),
		KTime:            times.KTime(ptr.ktime),
	}

	// Trace fields included in the hash:
	//  - PID, kernel stack ID, length & frame array
	// Intentionally excluded:
	//  - ktime, COMM, APM trace, APM transaction ID
	ptr.comm = [16]C.char{}
	ptr.apm_trace_id = C.ApmTraceID{}
	ptr.apm_transaction_id = C.ApmSpanID{}
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

	if ptr.custom_labels_hash != 0 {
		var lbls C.CustomLabelsArray

		if err := t.ebpfMaps["custom_labels"].Lookup(
			unsafe.Pointer(&ptr.custom_labels_hash), unsafe.Pointer(&lbls),
		); err != nil {
			log.Warnf("Failed to read custom labels: %v", err)
		}

		trace.CustomLabels = make(map[string]string, int(lbls.len))
		for i := 0; i < int(lbls.len); i++ {
			lbl := lbls.labels[i]
			key := string(lbl.key[0:(lbl.key_len)])
			val := string(lbl.val[0:(lbl.val_len)])
			trace.CustomLabels[key] = val
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
			File:          host.FileID(rawFrame.file_id),
			Lineno:        libpf.AddressOrLineno(rawFrame.addr_or_line),
			Type:          libpf.FrameType(rawFrame.kind),
			ReturnAddress: rawFrame.return_address != 0,
			LJCalleePC:    uint32(rawFrame.callee_pc_lo) + (uint32(rawFrame.callee_pc_hi) << 16),
			LJCallerPC:    uint32(rawFrame.caller_pc_lo) + (uint32(rawFrame.caller_pc_hi) << 16),
		}
	}

	return trace
}

// StartMapMonitors starts goroutines for collecting metrics and monitoring eBPF
// maps for tracepoints, new traces, trace count updates and unknown PCs.
func (t *Tracer) StartMapMonitors(ctx context.Context, traceOutChan chan *host.Trace) error {
	eventMetricCollector := t.startEventMonitor(ctx)

	startPollingPerfEventMonitor(ctx, t.ebpfMaps["trace_events"], t.intervals.TracePollInterval(),
		t.samplesPerSecond*int(unsafe.Sizeof(C.Trace{})), func(rawTrace []byte) {
			traceOutChan <- t.loadBpfTrace(rawTrace)
		})

	pidEvents := make([]uint32, 0)
	periodiccaller.StartWithManualTrigger(ctx, t.intervals.MonitorInterval(),
		t.triggerPIDProcessing, func(_ bool) {
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
	//nolint:lll
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
		C.metricID_UnwindApmIntErrReadTsdBase:                 metrics.IDUnwindApmIntErrReadTsdBase,
		C.metricID_UnwindApmIntErrReadCorrBufPtr:              metrics.IDUnwindApmIntErrReadCorrBufPtr,
		C.metricID_UnwindApmIntErrReadCorrBuf:                 metrics.IDUnwindApmIntErrReadCorrBuf,
		C.metricID_UnwindApmIntReadSuccesses:                  metrics.IDUnwindApmIntReadSuccesses,
		C.metricID_UnwindDotnetAttempts:                       metrics.IDUnwindDotnetAttempts,
		C.metricID_UnwindDotnetFrames:                         metrics.IDUnwindDotnetFrames,
		C.metricID_UnwindDotnetErrNoProcInfo:                  metrics.IDUnwindDotnetErrNoProcInfo,
		C.metricID_UnwindDotnetErrBadFP:                       metrics.IDUnwindDotnetErrBadFP,
		C.metricID_UnwindDotnetErrCodeHeader:                  metrics.IDUnwindDotnetErrCodeHeader,
		C.metricID_UnwindDotnetErrCodeTooLarge:                metrics.IDUnwindDotnetErrCodeTooLarge,
		C.metricID_UnwindLuaJITAttempts:                       metrics.IDUnwindLuaJITAttempts,
		C.metricID_UnwindLuaJITErrNoProcInfo:                  metrics.IDUnwindLuaJITErrNoProcInfo,
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
func (t *Tracer) AttachTracer() error {
	tracerProg, ok := t.ebpfProgs["native_tracer_entry"]
	if !ok {
		return errors.New("entry program is not available")
	}

	perfAttribute := new(perf.Attr)
	perfAttribute.SetSampleFreq(uint64(t.samplesPerSecond))
	if err := perf.CPUClock.Configure(perfAttribute); err != nil {
		return fmt.Errorf("failed to configure software perf event: %v", err)
	}

	onlineCPUIDs, err := getOnlineCPUIDs()
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
		return errors.New("no perf events available to enable for profiling")
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

	if rand.UintN(ProbabilisticThresholdMax) < threshold {
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
func (t *Tracer) StartProbabilisticProfiling(ctx context.Context) {
	metrics.Add(metrics.IDProbProfilingInterval,
		metrics.MetricValue(t.probabilisticInterval.Seconds()))

	// Run a single iteration of probabilistic profiling to avoid needing
	// to wait for the first interval to pass with periodiccaller.Start()
	// before getting called.
	t.probabilisticProfile(t.probabilisticInterval, t.probabilisticThreshold)

	periodiccaller.Start(ctx, t.probabilisticInterval, func() {
		t.probabilisticProfile(t.probabilisticInterval, t.probabilisticThreshold)
	})
}

// TraceProcessor gets the trace processor.
func (t *Tracer) TraceProcessor() tracehandler.TraceProcessor {
	return t.processManager
}
