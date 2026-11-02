// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package execinfomanager // import "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"

import (
	"errors"
	"fmt"
	"os"
	"time"

	lru "github.com/elastic/go-freelru"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/libc"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/lpm"
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
// - stack_delta_page_to_info
// - stack_delta_fp_ranges
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
	var (
		libcInfo *libc.LibcInfo
		ref      mapRef
	)

	// Fast path for executable info that is already present.
	state := mgr.state.WLock()
	info, err := state.takeExisting(fileID)
	if err != nil {
		mgr.state.WUnlock(&state)
		mgr.deferredFileIDs.Add(fileID, libpf.Void{})
		return ExecutableInfo{}, err
	}
	if info != nil {
		defer mgr.state.WUnlock(&state)
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
	if libc.IsPotentialLibcDSO(elfRef.FileName()) {
		if ef, errx := elfRef.GetELF(); errx == nil {
			libcInfo, _ = libc.ExtractLibcInfo(ef)
		}
	}

	// Re-take the lock and check whether another thread beat us to
	// inserting the data while we were waiting for the write lock.
	state = mgr.state.WLock()
	defer mgr.state.WUnlock(&state)
	info, err = state.takeExisting(fileID)
	if err != nil {
		mgr.deferredFileIDs.Add(fileID, libpf.Void{})
		return ExecutableInfo{}, err
	}
	if info != nil {
		return info.ExecutableInfo, nil
	}

	// Load the data into BPF maps.
	ref, err = state.loadDeltas(fileID, intervalData)
	if err != nil {
		if ref.MapID != 0 {
			// The rollback could not reclaim everything. Keep the leftovers as a
			// failed teardown, for CleanupUnused and takeExisting to retry.
			leftovers := &entry{mapRef: ref}
			state.markUnloadFailed(leftovers)
			state.executables[fileID] = leftovers
			state.unusedExecutables[fileID] = time.Now()
		}
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
		mapRef: ref,
		rc:     1,
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

	var err error
	for fileID, unusedSince := range state.unusedExecutables {
		if unusedSince.After(cutoff) {
			continue
		}

		// Report the invariant violations below without aborting the pass, so one bad entry
		// does not keep everything behind it in the maps. Nothing else drops their records.
		info, ok := state.executables[fileID]
		if !ok {
			delete(state.unusedExecutables, fileID)
			err = errors.Join(err, fmt.Errorf(
				"FileID %v is in state.unusedExecutables, but not in state.executables", fileID))
			continue
		}

		if info.rc != 0 {
			delete(state.unusedExecutables, fileID)
			err = errors.Join(err,
				fmt.Errorf("FileID %v has rc=%d when zero is expected", fileID, info.rc))
			continue
		}

		// The entry stays, as info.mapRef is the only record of the keys left in the maps.
		if derr := state.unloadDeltas(fileID, &info.mapRef); derr != nil {
			state.markUnloadFailed(info)
			err = errors.Join(err,
				fmt.Errorf("failed remove fileID 0x%x from BPF maps: %w", fileID, derr))
			continue
		}

		if info.Data != nil {
			info.Data.Unload(state.ebpf)
		}

		state.forgetExecutable(fileID, info)
	}

	return err
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
	summary[metrics.IDNumExeIDLoadedToEBPF] =
		metrics.MetricValue(len(state.executables) - state.numUnloadFailed)
	summary[metrics.IDUnwindInfoArraySize] = metrics.MetricValue(len(state.unwindInfoIndex))
	summary[metrics.IDHashmapNumStackDeltaPages] = metrics.MetricValue(state.numStackDeltaMapPages)
	summary[metrics.IDNumStackDeltaFPRanges] =
		metrics.MetricValue(state.numStackDeltaFPRanges)
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
	// - stack_delta_page_to_info
	// - stack_delta_fp_ranges
	// - exe_id_to_%d_stack_deltas
	executables map[host.FileID]*entry

	// unusedExecutables is an additional mapping from file ID to the time when their reference
	// counter reached zero.
	unusedExecutables map[host.FileID]time.Time

	// unwindInfoIndex maps each unique UnwindInfo to its array index within the corresponding
	// BPF map. This serves for de-duplication purposes. Elements are never removed. Entries are
	// synchronized with the unwind_info_array eBPF map.
	unwindInfoIndex map[sdtypes.UnwindInfo]uint16

	// numStackDeltaMapPages tracks the current size of the corresponding eBPF map.
	numStackDeltaMapPages uint64

	// numStackDeltaFPRanges tracks the current size of the stack_delta_fp_ranges LPM trie.
	numStackDeltaFPRanges uint64

	// numUnloadFailed counts the entries that exist for a teardown retry alone.
	numUnloadFailed int
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

// loadDeltas converts the intervals of an executable into the entries of the BPF maps and
// loads them.
func (state *executableInfoManagerState) loadDeltas(
	fileID host.FileID,
	intervals *sdtypes.IntervalData,
) (mapRef, error) {
	ebpfDeltas, resolving, dropped, err := intervals.StackDeltas(state.getUnwindInfoIndex)
	if err != nil {
		return mapRef{}, fmt.Errorf("failed to convert stack deltas of FileID %x: %w",
			fileID, err)
	}
	if dropped.OutOfSpan > 0 {
		log.Warnf("Skipped %d stack delta(s) of FileID %x outside the page span",
			dropped.OutOfSpan, fileID)
	}
	if dropped.OverLimit > 0 {
		log.Warnf("Skipped %d stack delta(s) of FileID %x over the per page limit",
			dropped.OverLimit, fileID)
	}
	if dropped.Descending > 0 {
		log.Warnf("Skipped %d stack delta(s) of FileID %x below their predecessor",
			dropped.Descending, fileID)
	}
	if len(ebpfDeltas) == 0 {
		// Either nothing was extracted or everything was dropped. Cache the result but
		// reserve no memory in the BPF maps.
		if intervals.NumDeltas > 0 {
			log.Warnf("All stack deltas of FileID %x were dropped", fileID)
		}
		return mapRef{MapID: 0}, nil
	}

	// Split the pages that have to resolve into the ones keeping a stack_delta_page_to_info
	// entry and the ones a frame-pointer range covers instead. The decision follows the delta
	// array the kernel reads, not the blocks behind it. Only the frame-pointer command is
	// ranged, as the other whole-block commands hardly ever reach across a page.
	fpUnwindInfo := support.DeltaCommandFlag | uint16(support.UnwindCommandFramePointer)
	pages := make([]pmebpf.StackDeltaPage, 0, len(resolving))
	omitted := make([]pmebpf.StackDeltaPage, 0, len(resolving))
	// fpRuns are the half open page ranges left out of the hash map. A run stops at each
	// page that keeps an entry, as the two lookups in get_stack_delta() are not atomic and
	// a range over such a page could answer for it.
	var fpRuns [][2]uint64
	for _, entry := range resolving {
		if entry.NumDeltas > 0 || entry.FirstDelta == 0 ||
			ebpfDeltas[entry.FirstDelta-1].UnwindInfo != fpUnwindInfo {
			pages = append(pages, entry)
			continue
		}
		omitted = append(omitted, entry)
		pageNum := entry.PageAddr >> support.StackDeltaPageBits
		if last := len(fpRuns) - 1; last >= 0 && fpRuns[last][1] == pageNum {
			fpRuns[last][1] = pageNum + 1
		} else {
			fpRuns = append(fpRuns, [2]uint64{pageNum, pageNum + 1})
		}
	}

	// The prefixes are calculated over page numbers, not addresses. A byte granular range
	// needs an order of magnitude more prefixes than it replaces pages.
	var fpPrefixes []lpm.Prefix
	for _, run := range fpRuns {
		prefixes, perr := lpm.CalculatePrefixList(run[0], run[1])
		if perr != nil {
			return mapRef{}, fmt.Errorf("failed to calculate FP prefixes for FileID %x: %v",
				fileID, perr)
		}
		fpPrefixes = append(fpPrefixes, prefixes...)
	}

	mapID, err := state.ebpf.UpdateExeIDToStackDeltas(fileID, ebpfDeltas)
	if err != nil {
		return mapRef{},
			fmt.Errorf("failed UpdateExeIDToStackDeltas for FileID %x: %v", fileID, err)
	}

	// The keys go into ref before the error of the update inserting them is checked, as it
	// may have inserted a part of them. An unrecorded key leaks, a stale one costs ENOENT.
	ref := mapRef{MapID: mapID}

	// The ranges go in first. Both orders are safe, as the two sets are disjoint, but the
	// ranges hold the bulk of the span and a full trie shows before the hash map is touched.
	leftover, rerr := state.ebpf.UpdateStackDeltaFPRanges(fileID, fpPrefixes, fpUnwindInfo)
	if rerr == nil {
		ref.FPPrefixes = fpPrefixes
		state.numStackDeltaFPRanges += uint64(len(fpPrefixes))
	} else {
		// Prefixes the rollback in UpdateStackDeltaFPRanges could not reclaim are still
		// in the trie, so the teardown keeps them. They cover the pages inserted below.
		ref.FPPrefixes = leftover
		state.numStackDeltaFPRanges += uint64(len(leftover))

		if !errors.Is(rerr, unix.ENOSPC) {
			// Only a full trie falls back, as the pages it inserts need no trie
			// entry. Anything else hits every executable and fills
			// stack_delta_page_to_info instead, failing the loads with E2BIG.
			return state.rollbackLoad(fileID, &ref,
				fmt.Errorf("failed UpdateStackDeltaFPRanges for FileID %x: %w",
					fileID, rerr))
		}

		log.Debugf("Falling back to %d stack delta pages for FileID %x: %v",
			len(omitted), fileID, rerr)
		pages = append(pages, omitted...)
	}

	perr := state.ebpf.UpdateStackDeltaPages(fileID, pages, mapID)
	for _, entry := range pages {
		ref.Pages = append(ref.Pages, entry.PageAddr)
	}
	state.numStackDeltaMapPages += uint64(len(pages))
	if perr != nil {
		return state.rollbackLoad(fileID, &ref,
			fmt.Errorf("failed UpdateStackDeltaPages for FileID %x: %v", fileID, perr))
	}

	return ref, nil
}

// rollbackLoad undoes a partial loadDeltas. Keys the teardown could not reclaim stay in ref,
// which the caller then has to keep, and a fully reclaimed load leaves ref.MapID zero.
func (state *executableInfoManagerState) rollbackLoad(fileID host.FileID, ref *mapRef,
	cause error,
) (mapRef, error) {
	if err := state.unloadDeltas(fileID, ref); err != nil {
		return *ref, errors.Join(cause,
			fmt.Errorf("failed to roll back the load of FileID %x: %w", fileID, err))
	}
	return mapRef{}, cause
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

// markUnloadFailed keeps info for a teardown retry and stops counting it as loaded.
func (state *executableInfoManagerState) markUnloadFailed(info *entry) {
	if !info.unloadFailed {
		info.unloadFailed = true
		state.numUnloadFailed++
	}
}

// forgetExecutable drops all bookkeeping for fileID. Its BPF entries have to be gone by then.
func (state *executableInfoManagerState) forgetExecutable(fileID host.FileID, info *entry) {
	if info.unloadFailed {
		state.numUnloadFailed--
	}
	delete(state.executables, fileID)
	delete(state.unusedExecutables, fileID)
}

// takeExisting returns the cached entry for fileID with its reference count incremented, or
// nil when the executable has to be loaded from scratch. An entry whose teardown did not
// finish is not revived, as a part of its BPF state is gone and nothing reinserts it, so the
// teardown is finished and the entry dropped instead.
func (state *executableInfoManagerState) takeExisting(fileID host.FileID) (*entry, error) {
	info, ok := state.executables[fileID]
	if !ok {
		return nil, nil
	}

	if info.unloadFailed {
		// The flag is only ever set with rc == 0 and this lock held, so there is no
		// reference to invalidate here.
		if err := state.unloadDeltas(fileID, &info.mapRef); err != nil {
			return nil, fmt.Errorf(
				"failed to finish the teardown of fileID 0x%x: %w", fileID, err)
		}
		if info.Data != nil {
			info.Data.Unload(state.ebpf)
		}
		state.forgetExecutable(fileID, info)
		return nil, nil
	}

	info.rc++
	if info.rc == 1 {
		delete(state.unusedExecutables, fileID)
	}
	return info, nil
}

// unloadDeltas removes what loadDeltas added from our BPF maps. On failure ref is left with
// the entries still in the maps, so that the call can be repeated with the same ref.
func (state *executableInfoManagerState) unloadDeltas(
	fileID host.FileID,
	ref *mapRef,
) error {
	if ref.MapID == 0 {
		// Nothing to do: no data was inserted in the first place.
		return nil
	}

	// A range covers only pages without a hash entry, so either order is safe for a lockless
	// get_stack_delta(), while the stack delta data has to outlive the pages referencing it.
	failed, rangeErr := state.ebpf.DeleteStackDeltaFPRanges(fileID, ref.FPPrefixes)
	// The counter follows ref, not the deletes. A prefix leaving ref.FPPrefixes is no
	// longer in the trie, whether it was deleted or never inserted.
	if removed := len(ref.FPPrefixes) - len(failed); removed > 0 {
		state.numStackDeltaFPRanges -= uint64(removed)
	}
	ref.FPPrefixes = failed
	if rangeErr != nil {
		rangeErr = fmt.Errorf("failed to remove stack delta FP ranges: %w", rangeErr)
	}

	// Keep only the pages whose removal failed, as those are what a retry must redo.
	var pageErr error
	remaining := ref.Pages[:0]
	for _, pageAddr := range ref.Pages {
		if derr := state.ebpf.DeleteStackDeltaPage(fileID, pageAddr); derr != nil {
			pageErr = errors.Join(pageErr,
				fmt.Errorf("failed to remove stack delta page %#x: %w", pageAddr, derr))
			remaining = append(remaining, pageAddr)
			continue
		}
		state.numStackDeltaMapPages--
	}
	ref.Pages = remaining
	if err := errors.Join(rangeErr, pageErr); err != nil {
		// A surviving page references the stack delta data, and a surviving prefix
		// needs ref.MapID set for the retry to get here at all.
		return err
	}

	// Now remove the actual stack delta data after all references are removed.
	if err := state.ebpf.DeleteExeIDToStackDeltas(fileID, ref.MapID); err != nil {
		return err
	}
	// Everything is gone, so a redundant retry becomes a no-op.
	ref.MapID = 0
	return nil
}

// entry is the type used in the EIM executable map.
type entry struct {
	// ExecutableInfo is the public portion of the EIM entry.
	ExecutableInfo
	// mapRef stores info for identifying associated data in BPF maps.
	mapRef mapRef
	// rc determines in how many processes this executable is currently loaded.
	rc uint64
	// unloadFailed is set when unloadDeltas left entries behind in the BPF maps. The entry
	// then exists only for a teardown retry, and takeExisting must not hand it out.
	unloadFailed bool
}

// mapRef stores all info required to identify and remove
// all data for an executable from our BPF maps.
type mapRef struct {
	// Pages lists the page addresses that have an entry in stack_delta_page_to_info. They
	// are sparse, as a page covered by a frame-pointer range keeps none, so a start page
	// and a count cannot describe them. At most sdtypes.MaxPageSpan of them.
	Pages []uint64
	// FPPrefixes lists the stack_delta_fp_ranges prefixes covering the omitted pages.
	FPPrefixes []lpm.Prefix
	MapID      uint16
}
