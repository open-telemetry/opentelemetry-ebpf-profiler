// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package execinfomanager // import "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"

import (
	"errors"
	"fmt"
	"os"
	"time"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	// deferredFileIDSize defines the maximum size of the deferredFileIDs LRU
	// cache that contains file IDs for which stack delta extraction is deferred
	// to avoid busy loops.
	deferredFileIDSize = 8192
	// TTL of entries in the deferredFileIDs LRU cache.
	deferredFileIDTimeout = 90 * time.Second
)

// ErrDeferredFileID indicates that handling of stack deltas for a file ID failed
// and should only be tried again at a later point.
var ErrDeferredFileID = errors.New("deferred FileID")

// ExecutableInfo stores information about an executable (ELF file).
type ExecutableInfo struct {
	// Data stores per-executable interpreter information if the file ID that this
	// instance belongs to was previously identified as an interpreter. Otherwise,
	// this field is nil.
	Data interpreter.Data
	// LibcInfo stores libc information if the executable is libc, otherwise nil.
	LibcInfo *libc.LibcInfo
}

// ExecutableInfoManager manages all per-executable (FileID) information that we require to
// perform our native and interpreter unwinding. Executable information is de-duplicated between
// processes and is kept around as long as there is at least one process that is known to have
// the corresponding FileID loaded (reference counting). Tracking loaded executables is left to
// the caller.
//
// The manager is synchronized internally and all public methods can be called from an arbitrary
// number of threads simultaneously.
//
// The manager is responsible for managing entries in the following BPF maps:
//
// - exe_id_to_stackdelta_meta
// - exe_id_to_%d_stack_deltas
// - unwind_info_array
// - interpreter_offsets
//
// All of these maps can be read by anyone, but are written to exclusively by this manager.
type ExecutableInfoManager struct {
	// sdp allows fetching stack deltas for executables.
	sdp nativeunwind.StackDeltaProvider

	// state bundles up all mutable state of the manager.
	state xsync.RWMutex[executableInfoManagerState]

	// deferredFileIDs caches file IDs for which stack delta extraction failed and
	// retrying extraction of stack deltas should be deferred for some time.
	deferredFileIDs *lru.SyncedLRU[host.FileID, libpf.Void]
}

// NewExecutableInfoManager creates a new instance of the executable info manager.
func NewExecutableInfoManager(
	sdp nativeunwind.StackDeltaProvider,
	ebpf pmebpf.EbpfHandler,
	interpretersConfig interpreterconfig.Config,
) (*ExecutableInfoManager, error) {
	loaders := interpretersConfig.Loaders()

	deferredFileIDs, err := lru.NewSynced[host.FileID, libpf.Void](deferredFileIDSize,
		func(id host.FileID) uint32 { return uint32(id) })
	if err != nil {
		return nil, err
	}
	deferredFileIDs.SetLifetime(deferredFileIDTimeout)

	return &ExecutableInfoManager{
		sdp: sdp,
		state: xsync.NewRWMutex(executableInfoManagerState{
			interpreterLoaders: loaders,
			executables:        map[host.FileID]*entry{},
			unusedExecutables:  map[host.FileID]time.Time{},
			unwindInfoIndex:    map[sdtypes.UnwindInfo]uint16{},
			ebpf:               ebpf,
		}),
		deferredFileIDs: deferredFileIDs,
	}, nil
}

// AddOrIncRef either adds information about an executable to the internal cache (when first
// encountering it) or increments the reference count if the executable is already known.
//
// The return value is copied instead of returning a pointer in order to spare us the use
// of getters and more complicated locking semantics.
func (mgr *ExecutableInfoManager) AddOrIncRef(fileID host.FileID,
	elfRef *pfelf.Reference,
) (ExecutableInfo, error) {
	if _, exists := mgr.deferredFileIDs.Get(fileID); exists {
		return ExecutableInfo{}, ErrDeferredFileID
	}

	// Fast path for executable info that is already present.
	state := mgr.state.WLock()
	info, ok := state.executables[fileID]
	if ok {
		defer mgr.state.WUnlock(&state)
		info.rc++
		if info.rc == 1 {
			delete(state.unusedExecutables, fileID)
		}
		return info.ExecutableInfo, nil
	}

	// Otherwise, gather interval data via SDP. This can take a while,
	// so we release the lock before doing this.
	mgr.state.WUnlock(&state)

	intervalData, err := mgr.sdp.GetIntervalDataForFile(elfRef)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			mgr.deferredFileIDs.Add(fileID, libpf.Void{})
		}
		return ExecutableInfo{}, fmt.Errorf("failed to extract interval data: %w", err)
	}
	if len(intervalData.Blocks) == 0 {
		ef, errx := elfRef.GetELF()
		if errx != nil {
			return ExecutableInfo{}, errx
		}
		intervalData = synthesizeIntervalData(ef)
	}

	// Also gather Libc info if applicable.
	var libcInfo *libc.LibcInfo
	if libc.IsPotentialLibcDSO(elfRef.FileName()) {
		if ef, errx := elfRef.GetELF(); errx == nil {
			libcInfo, _ = libc.ExtractLibcInfo(ef)
		}
	}

	// Re-take the lock and check whether another thread beat us to
	// inserting the data while we were waiting for the write lock.
	state = mgr.state.WLock()
	defer mgr.state.WUnlock(&state)
	if info, ok = state.executables[fileID]; ok {
		info.rc++
		if info.rc == 1 {
			delete(state.unusedExecutables, fileID)
		}
		return info.ExecutableInfo, nil
	}

	// Load the data into BPF maps.
	mapID, err := state.loadDeltas(fileID, intervalData)
	if err != nil {
		mgr.deferredFileIDs.Add(fileID, libpf.Void{})
		return ExecutableInfo{}, fmt.Errorf("failed to load deltas: %w", err)
	}

	// Create the LoaderInfo for interpreter detection
	loaderInfo := interpreter.NewLoaderInfo(fileID, elfRef, intervalData)

	// Detect and load interpreter data
	interpData := state.detectAndLoadInterpData(loaderInfo)

	// Insert a corresponding record into our map.
	info = &entry{
		ExecutableInfo: ExecutableInfo{
			Data:     interpData,
			LibcInfo: libcInfo,
		},
		mapID: mapID,
		rc:    1,
	}
	state.executables[fileID] = info

	return info.ExecutableInfo, nil
}

// DecRef decrements the reference counter of the executable being tracked.
func (mgr *ExecutableInfoManager) DecRef(fileID host.FileID) error {
	state := mgr.state.WLock()
	defer mgr.state.WUnlock(&state)

	info, ok := state.executables[fileID]
	if !ok {
		return fmt.Errorf("FileID %v is not known to ExecutableInfoManager", fileID)
	}

	if info.rc == 0 {
		// This should be unreachable.
		return errors.New("state corruption in ExecutableInfoManager: encountered 0 RC")
	}

	info.rc--

	if info.rc == 0 {
		state.unusedExecutables[fileID] = time.Now()
	}

	return nil
}

// CleanupUnused removes tracked executables for which reference counter has reached zero
// more than `age` ago. During cleanup information about the file is removed from the manager
// and the corresponding BPF maps.
func (mgr *ExecutableInfoManager) CleanupUnused(age time.Duration) error {
	state := mgr.state.WLock()
	defer mgr.state.WUnlock(&state)

	cutoff := time.Now().Add(-age)

	for fileID, unusedSince := range state.unusedExecutables {
		if unusedSince.After(cutoff) {
			continue
		}

		info, ok := state.executables[fileID]
		if !ok {
			return fmt.Errorf("FileID %v is in state.unusedExecutables, but not in state.executables", fileID)
		}

		if info.rc != 0 {
			return fmt.Errorf("FileID %v has rc=%d when zero is expected", fileID, info.rc)
		}

		if err := state.unloadDeltas(fileID, info.mapID); err != nil {
			return fmt.Errorf("failed remove fileID 0x%x from BPF maps: %w", fileID, err)
		}

		if info.Data != nil {
			info.Data.Unload(state.ebpf)
		}

		delete(state.executables, fileID)
		delete(state.unusedExecutables, fileID)
	}

	return nil
}

// NumInterpreterLoaders returns the number of interpreter loaders that are enabled.
func (mgr *ExecutableInfoManager) NumInterpreterLoaders() int {
	state := mgr.state.RLock()
	defer mgr.state.RUnlock(&state)
	return len(state.interpreterLoaders)
}

// UpdateMetricSummary updates the metrics in the given metric map.
func (mgr *ExecutableInfoManager) UpdateMetricSummary(summary metrics.Summary) {
	state := mgr.state.RLock()
	summary[metrics.IDNumExeIDLoadedToEBPF] = metrics.MetricValue(len(state.executables))
	summary[metrics.IDUnwindInfoArraySize] = metrics.MetricValue(len(state.unwindInfoIndex))
	mgr.state.RUnlock(&state)

	deltaProviderStatistics := mgr.sdp.GetAndResetStatistics()
	summary[metrics.IDStackDeltaProviderSuccess] = metrics.MetricValue(deltaProviderStatistics.Success)
	summary[metrics.IDStackDeltaProviderExtractionError] = metrics.MetricValue(deltaProviderStatistics.ExtractionErrors)
}

type executableInfoManagerState struct {
	// interpreterLoaders is a list of loaders, each providing functionality
	// for loading the host agent support for a specific interpreter type.
	interpreterLoaders []interpreter.Loader

	// ebpf provides the interface to manipulate eBPF maps.
	ebpf pmebpf.EbpfHandler

	// executables is the primary mapping from file ID to executable information. Entries are
	// managed with reference counting and are synchronized with various eBPF maps:
	//
	// - exe_id_to_stackdelta_meta
	// - exe_id_to_%d_stack_deltas
	executables map[host.FileID]*entry

	// unusedExecutables is an additional mapping from file ID to the time when their reference
	// counter reached zero.
	unusedExecutables map[host.FileID]time.Time

	// unwindInfoIndex maps each unique UnwindInfo to its array index within the corresponding
	// BPF map. This serves for de-duplication purposes. Elements are never removed. Entries are
	// synchronized with the unwind_info_array eBPF map.
	unwindInfoIndex map[sdtypes.UnwindInfo]uint16
}

// detectAndLoadInterpData attempts to detect the given executable as an interpreter. If detection
// succeeds, it then loads additional per-interpreter data into the BPF maps and returns the
// interpreter data. If multiple loaders recognize the executable, it returns a MultiInterpreter.
func (state *executableInfoManagerState) detectAndLoadInterpData(
	loaderInfo *interpreter.LoaderInfo,
) interpreter.Data {
	var matches []interpreter.Data //nolint:prealloc

	// Ask all interpreter loaders whether they want to handle this executable.
	for _, loader := range state.interpreterLoaders {
		data, err := loader.Load(state.ebpf, loaderInfo)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Very common if the process exited when we tried to analyze it.
				log.Debugf("Failed to load %v (%#016x): file not found",
					loaderInfo.FileName(), loaderInfo.FileID())
			} else {
				log.Warnf("Failed to load %v (%#016x): %v",
					loaderInfo.FileName(), loaderInfo.FileID(), err)
			}
			// Continue checking other loaders even if one fails
			continue
		}
		if data == nil {
			continue
		}

		log.Debugf("Interpreter data %v for %v (%#016x)",
			data, loaderInfo.FileName(), loaderInfo.FileID())
		matches = append(matches, data)
	}

	// Return based on how many interpreters matched
	switch len(matches) {
	case 0:
		return nil
	case 1:
		return matches[0]
	default:
		log.Debugf("Multiple interpreters (%d) matched for %v (%#016x)",
			len(matches), loaderInfo.FileName(), loaderInfo.FileID())
		return interpreter.NewMultiData(matches)
	}
}

// loadDeltas converts the sdtypes.StackDelta to StackDelta and passes that to
// the ebpf interface to be loaded to kernel maps, building a page descriptor
// for every 64kB page covering the deltas.
func (state *executableInfoManagerState) loadDeltas(
	fileID host.FileID,
	intervals *sdtypes.IntervalData,
) (uint16, error) {
	numDeltas := intervals.NumDeltas
	if numDeltas == 0 {
		// If no deltas are extracted, cache the result but don't reserve memory in BPF maps.
		return 0, nil
	}

	// Index the unwind-info. The page descriptors are built in the same loop:
	// each descriptor covers one 64kB page and points to the range of the
	// page's own delta pairs. Pages without own deltas get an empty range
	// that resolves via the descriptor's fallback unwind info: the covering
	// delta's info with its merge opcode adjustment resolved. Merges never
	// cross page boundaries, so one info covers the whole fallback range.
	var fallbackInfo sdtypes.UnwindInfo
	var firstPage, lastPage, lastAddr uint64
	ebpfDeltas := make([]pmebpf.StackDelta, 0, numDeltas)
	pageDescs := make([]pmebpf.StackDeltaPageDesc, 0,
		int(intervals.Blocks[len(intervals.Blocks)-1].End>>support.StackDeltaPageBits-
			intervals.Blocks[0].Start>>support.StackDeltaPageBits)+1)
	closePage := func() {
		// Every page slice must be padded to a pair boundary for the binary
		// search to work. Duplicate the page's last delta for padding if needed.
		if len(ebpfDeltas)%2 == 1 {
			ebpfDeltas = append(ebpfDeltas, ebpfDeltas[len(ebpfDeltas)-1])
		}
		last := &pageDescs[len(pageDescs)-1]
		last.NumPairs = uint16(uint32(len(ebpfDeltas))/2 - last.FirstPair)
	}
	addDelta := func(addr uint64, info support.UnwindInfo) error {
		if addr < lastAddr {
			return nil
		}
		unwindInfoIndex, err := state.getUnwindInfoIndex(info)
		if err != nil {
			return err
		}
		if numDeltas := len(ebpfDeltas); numDeltas > 0 &&
			ebpfDeltas[numDeltas-1].UnwindInfo == unwindInfoIndex {
			// Deduplicate consecutive deltas with identical unwind info.
			return nil
		}
		page := addr >> support.StackDeltaPageBits
		if len(pageDescs) == 0 {
			firstPage, lastPage = page, page
			// The first page has no covering delta: report the PCs below
			// its first own delta as invalid (STACK_DELTA_INVALID).
			pageDescs = append(pageDescs, pmebpf.StackDeltaPageDesc{
				FirstPair:    0,
				FallbackInfo: uint16(support.DeltaCommandFlag | support.UnwindCommandInvalid),
			})
		} else {
			if page != lastPage {
				closePage()
				// Resolve the covering delta's pending merge opcode.
				if fallbackInfo.MergeOpcode != 0 {
					if fallbackInfo.MergeOpcode&support.MergeOpcodeNegative != 0 {
						fallbackInfo.Param -= 8
					} else {
						fallbackInfo.Param += 8
					}
					fallbackInfo.MergeOpcode = 0
				}
				fallbackIndex, err := state.getUnwindInfoIndex(fallbackInfo)
				if err != nil {
					return err
				}
				for p := lastPage + 1; p <= page; p++ {
					pageDescs = append(pageDescs, pmebpf.StackDeltaPageDesc{
						FirstPair:    uint32(len(ebpfDeltas)) / 2,
						FallbackInfo: fallbackIndex,
					})
				}
			}
		}
		lastPage = page
		lastAddr = addr
		ebpfDeltas = append(ebpfDeltas, pmebpf.StackDelta{
			AddrLow:    uint16(addr),
			UnwindInfo: unwindInfoIndex,
		})
		fallbackInfo = info
		return nil
	}

	var unwindInfo sdtypes.UnwindInfo
	for blockIndex, block := range intervals.Blocks {
		for deltaIndex, delta := range block.Deltas {
			if unwindInfo.MergeOpcode != 0 {
				// This delta was merged in the previous iteration.
				unwindInfo.MergeOpcode = 0
				continue
			}
			unwindInfo = delta.Info
			if deltaIndex+1 < len(block.Deltas) {
				// Do not merge deltas across 64kB page boundaries: the
				// fallback info of a page must stay a single unwind info.
				addr := block.Start + uint64(delta.Offset)
				nextAddr := block.Start + uint64(block.Deltas[deltaIndex+1].Offset)
				if addr>>support.StackDeltaPageBits == nextAddr>>support.StackDeltaPageBits {
					unwindInfo.MergeOpcode = calculateMergeOpcode(delta, block.Deltas[deltaIndex+1])
				}
			}

			addr := block.Start + uint64(delta.Offset)
			if unwindInfo.Flags&support.UnwindFlagCommand != 0 && unwindInfo.Param == support.UnwindCommandSignal {
				// EBPF code does a -1 fixup for return addresses.
				// To match the signal handler function injected into
				// stack, the signal handler stack delta must start one
				// byte earlier to accommodate for the ebpf fixup.
				// C-libraries will have a 'nop' inserted to make sure
				// nothing conflicts.
				addr--
			}

			// Uses the new 'unwindInfo' with potentially updated MergeOpcode
			// here. In the end, it's only the unwindInfoIndex being different for
			// merged deltas.
			if err := addDelta(addr, unwindInfo); err != nil {
				return 0, err
			}
		}
		// Check if blocks are far apart or last block
		if blockIndex+1 == len(intervals.Blocks) || block.End+sdtypes.MinimumGap < intervals.Blocks[blockIndex+1].Start {
			if err := addDelta(block.End, sdtypes.UnwindInfoInvalid); err != nil {
				return 0, err
			}
		}
	}

	// Close the last page. FirstPair values stay relative to the start of
	// the pair region, which the inner map holds after the page descriptors.
	closePage()

	// The page descriptors precede the pair region in the inner map: offset
	// the FirstPair values by the descriptor count to index the pairs.
	for index := range pageDescs {
		pageDescs[index].FirstPair += uint32(len(pageDescs))
	}

	// Update data to eBPF
	mapID, err := state.ebpf.UpdateExeIDToStackDeltas(fileID, ebpfDeltas, pageDescs, firstPage)
	if err != nil {
		return 0,
			fmt.Errorf("failed UpdateExeIDToStackDeltas for FileID %x: %v", fileID, err)
	}

	return mapID, nil
}

// calculateMergeOpcode calculates the merge opcode byte given two consecutive StackDeltas.
// Zero means no merging happened. Only small differences for address and the CFA delta
// are considered, in order to limit the amount of unique combinations generated.
func calculateMergeOpcode(delta, nextDelta sdtypes.StackDelta) uint8 {
	if delta.Info.Flags&support.UnwindFlagCommand != 0 {
		return 0
	}
	addrDiff := nextDelta.Offset - delta.Offset
	if addrDiff < 1 || addrDiff > 2 {
		return 0
	}
	if nextDelta.Info.BaseReg != delta.Info.BaseReg ||
		nextDelta.Info.AuxBaseReg != delta.Info.AuxBaseReg ||
		nextDelta.Info.AuxParam != delta.Info.AuxParam {
		return 0
	}
	paramDiff := nextDelta.Info.Param - delta.Info.Param
	switch paramDiff {
	case 8:
		return uint8(addrDiff)
	case -8:
		return uint8(addrDiff) | support.MergeOpcodeNegative
	}
	return 0
}

// getUnwindInfoIndex maps the given UnwindInfo to its eBPF array index. This can be direct
// encoding, or index to the unwind info array (new index is created if needed).
// See STACK_DELTA_COMMAND_FLAG for further explanation of the directly encoded unwind infos.
func (state *executableInfoManagerState) getUnwindInfoIndex(
	info sdtypes.UnwindInfo,
) (uint16, error) {
	if info.Flags&support.UnwindFlagCommand != 0 {
		return uint16(info.Param) | support.DeltaCommandFlag, nil
	}

	if index, ok := state.unwindInfoIndex[info]; ok {
		return index, nil
	}
	index := uint16(len(state.unwindInfoIndex))
	if err := state.ebpf.UpdateUnwindInfo(index, info); err != nil {
		return 0, fmt.Errorf("failed to insert unwind info #%d: %v", index, err)
	}
	state.unwindInfoIndex[info] = index
	return index, nil
}

// unloadDeltas removes information that was previously added by loadDeltas from our BPF maps.
func (state *executableInfoManagerState) unloadDeltas(fileID host.FileID, mapID uint16) error {
	if mapID == 0 {
		// Nothing to do: no data was inserted in the first place.
		return nil
	}

	// DeleteExeIDToStackDeltas removes first the stack delta meta entry that
	// references the stack delta data, and then the stack delta data itself.
	return state.ebpf.DeleteExeIDToStackDeltas(fileID, mapID)
}

// entry is the type used in the EIM executable map.
type entry struct {
	// ExecutableInfo is the public portion of the EIM entry.
	ExecutableInfo
	// mapID identifies the associated data of the executable in the BPF maps.
	mapID uint16
	// rc determines in how many processes this executable is currently loaded.
	rc uint64
}
