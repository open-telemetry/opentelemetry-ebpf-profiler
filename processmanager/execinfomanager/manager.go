// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package execinfomanager // import "go.opentelemetry.io/ebpf-profiler/processmanager/execinfomanager"

import (
	"errors"
	"fmt"
	"os"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/interpreter/apmint"
	"go.opentelemetry.io/ebpf-profiler/interpreter/customlabels"
	"go.opentelemetry.io/ebpf-profiler/interpreter/dotnet"
	"go.opentelemetry.io/ebpf-profiler/interpreter/golang"
	"go.opentelemetry.io/ebpf-profiler/interpreter/hotspot"
	"go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"
	"go.opentelemetry.io/ebpf-profiler/interpreter/perl"
	"go.opentelemetry.io/ebpf-profiler/interpreter/php"
	"go.opentelemetry.io/ebpf-profiler/interpreter/python"
	"go.opentelemetry.io/ebpf-profiler/interpreter/ruby"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpf"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/tpbase"
	"go.opentelemetry.io/ebpf-profiler/util"
)

const (
	// minimumMemoizableGapSize is the minimum size for a gap for it to be
	// recorded. Currently reflects the V8 binary blob size, in which
	// the gap size is >= 512kB.
	minimumMemoizableGapSize = 512 * 1024

	// deferredFileIDSize defines the maximum size of the deferredFileIDs LRU
	// cache that contains file IDs for which stack delta extraction is deferred
	// to avoid busy loops.
	deferredFileIDSize = 8192
	// TTL of entries in the deferredFileIDs LRU cache.
	deferredFileIDTimeout = 90 * time.Second
)

var (
	// ErrDeferredFileID indicates that handling of stack deltas for a file ID failed
	// and should only be tried again at a later point.
	ErrDeferredFileID = errors.New("deferred FileID")
)

// ExecutableInfo stores information about an executable (ELF file).
type ExecutableInfo struct {
	// Data stores per-executable interpreter information if the file ID that this
	// instance belongs to was previously identified as an interpreter. Otherwise,
	// this field is nil.
	Data interpreter.Data
	// TSDInfo stores TSD information if the executable is libc, otherwise nil.
	TSDInfo *tpbase.TSDInfo
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
	includeTracers types.IncludedTracers,
	collectCustomLabels bool,
) (*ExecutableInfoManager, error) {
	// Initialize interpreter loaders.
	interpreterLoaders := make([]interpreter.Loader, 0)
	if includeTracers.Has(types.PerlTracer) {
		interpreterLoaders = append(interpreterLoaders, perl.Loader)
	}
	if includeTracers.Has(types.PythonTracer) {
		interpreterLoaders = append(interpreterLoaders, python.Loader)
	}
	if includeTracers.Has(types.PHPTracer) {
		interpreterLoaders = append(interpreterLoaders, php.Loader, php.OpcacheLoader)
	}
	if includeTracers.Has(types.HotspotTracer) {
		interpreterLoaders = append(interpreterLoaders, hotspot.Loader)
	}
	if includeTracers.Has(types.RubyTracer) {
		interpreterLoaders = append(interpreterLoaders, ruby.Loader)
	}
	if includeTracers.Has(types.V8Tracer) {
		interpreterLoaders = append(interpreterLoaders, nodev8.Loader)
	}
	if includeTracers.Has(types.DotnetTracer) {
		interpreterLoaders = append(interpreterLoaders, dotnet.Loader)
	}

	interpreterLoaders = append(interpreterLoaders, apmint.Loader)
	if collectCustomLabels {
		interpreterLoaders = append(interpreterLoaders, golang.Loader, customlabels.Loader)
	}

	deferredFileIDs, err := lru.NewSynced[host.FileID, libpf.Void](deferredFileIDSize,
		func(id host.FileID) uint32 { return uint32(id) })
	if err != nil {
		return nil, err
	}
	deferredFileIDs.SetLifetime(deferredFileIDTimeout)

	return &ExecutableInfoManager{
		sdp: sdp,
		state: xsync.NewRWMutex(executableInfoManagerState{
			interpreterLoaders: interpreterLoaders,
			executables:        map[host.FileID]*entry{},
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
	elfRef *pfelf.Reference) (ExecutableInfo, error) {
	if _, exists := mgr.deferredFileIDs.Get(fileID); exists {
		return ExecutableInfo{}, ErrDeferredFileID
	}
	var (
		intervalData sdtypes.IntervalData
		tsdInfo      *tpbase.TSDInfo
		ref          mapRef
		gaps         []util.Range
		err          error
	)

	// Fast path for executable info that is already present.
	state := mgr.state.WLock()
	info, ok := state.executables[fileID]
	if ok {
		defer mgr.state.WUnlock(&state)
		info.rc++
		return info.ExecutableInfo, nil
	}

	// Otherwise, gather interval data via SDP. This can take a while,
	// so we release the lock before doing this.
	mgr.state.WUnlock(&state)

	if err = mgr.sdp.GetIntervalStructuresForFile(fileID, elfRef, &intervalData); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			mgr.deferredFileIDs.Add(fileID, libpf.Void{})
		}
		return ExecutableInfo{}, fmt.Errorf("failed to extract interval data: %w", err)
	}

	// Also gather TSD info if applicable.
	if tpbase.IsPotentialTSDDSO(elfRef.FileName()) {
		if ef, errx := elfRef.GetELF(); errx == nil {
			tsdInfo, _ = tpbase.ExtractTSDInfo(ef)
		}
	}

	// Re-take the lock and check whether another thread beat us to
	// inserting the data while we were waiting for the write lock.
	state = mgr.state.WLock()
	defer mgr.state.WUnlock(&state)
	if info, ok = state.executables[fileID]; ok {
		info.rc++
		return info.ExecutableInfo, nil
	}

	// Load the data into BPF maps.
	ref, gaps, err = state.loadDeltas(fileID, intervalData.Deltas)
	if err != nil {
		mgr.deferredFileIDs.Add(fileID, libpf.Void{})
		return ExecutableInfo{}, fmt.Errorf("failed to load deltas: %w", err)
	}

	// Create the LoaderInfo for interpreter detection
	loaderInfo := interpreter.NewLoaderInfo(fileID, elfRef, gaps)

	// Insert a corresponding record into our map.
	info = &entry{
		ExecutableInfo: ExecutableInfo{
			Data:    state.detectAndLoadInterpData(loaderInfo),
			TSDInfo: tsdInfo,
		},
		mapRef: ref,
		rc:     1,
	}
	state.executables[fileID] = info

	return info.ExecutableInfo, nil
}

// AddSynthIntervalData should only be called once for a given file ID. It will error if it or
// AddOrIncRef has been previously called for the same file ID. Interpreter detection is skipped.
func (mgr *ExecutableInfoManager) AddSynthIntervalData(
	fileID host.FileID,
	data sdtypes.IntervalData,
) error {
	state := mgr.state.WLock()
	defer mgr.state.WUnlock(&state)

	if _, exists := state.executables[fileID]; exists {
		return errors.New("AddSynthIntervalData: mapping already exists")
	}

	ref, _, err := state.loadDeltas(fileID, data.Deltas)
	if err != nil {
		return fmt.Errorf("failed to load deltas: %w", err)
	}

	state.executables[fileID] = &entry{
		ExecutableInfo: ExecutableInfo{Data: nil},
		mapRef:         ref,
		rc:             1,
	}

	return nil
}

// RemoveOrDecRef decrements the reference counter of the executable being tracked. Once the RC
// reaches zero, information about the file is removed from the manager and the corresponding
// BPF maps.
func (mgr *ExecutableInfoManager) RemoveOrDecRef(fileID host.FileID) error {
	state := mgr.state.WLock()
	defer mgr.state.WUnlock(&state)

	info, ok := state.executables[fileID]
	if !ok {
		return fmt.Errorf("FileID %v is not known to ExecutableInfoManager", fileID)
	}

	switch info.rc {
	case 1:
		// This was the last reference: clean up all associated resources.
		if err := state.unloadDeltas(fileID, &info.mapRef); err != nil {
			return fmt.Errorf("failed remove fileID 0x%x from BPF maps: %w", fileID, err)
		}
		delete(state.executables, fileID)
	case 0:
		// This should be unreachable.
		return errors.New("state corruption in ExecutableInfoManager: encountered 0 RC")
	default:
		info.rc--
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
	summary[metrics.IDNumExeIDLoadedToEBPF] =
		metrics.MetricValue(len(state.executables))
	summary[metrics.IDUnwindInfoArraySize] =
		metrics.MetricValue(len(state.unwindInfoIndex))
	summary[metrics.IDHashmapNumStackDeltaPages] =
		metrics.MetricValue(state.numStackDeltaMapPages)
	mgr.state.RUnlock(&state)

	deltaProviderStatistics := mgr.sdp.GetAndResetStatistics()
	summary[metrics.IDStackDeltaProviderSuccess] =
		metrics.MetricValue(deltaProviderStatistics.Success)
	summary[metrics.IDStackDeltaProviderExtractionError] =
		metrics.MetricValue(deltaProviderStatistics.ExtractionErrors)
}

type executableInfoManagerState struct {
	// interpreterLoaders is a list of instances of an interface that provide functionality
	// for loading the host agent support for a specific interpreter type.
	interpreterLoaders []interpreter.Loader

	// ebpf provides the interface to manipulate eBPF maps.
	ebpf pmebpf.EbpfHandler

	// executables is the primary mapping from file ID to executable information. Entries are
	// managed with reference counting and are synchronized with various eBPF maps:
	//
	// - stack_delta_page_to_info
	// - exe_id_to_%d_stack_deltas
	executables map[host.FileID]*entry

	// unwindInfoIndex maps each unique UnwindInfo to its array index within the corresponding
	// BPF map. This serves for de-duplication purposes. Elements are never removed. Entries are
	// synchronized with the unwind_info_array eBPF map.
	unwindInfoIndex map[sdtypes.UnwindInfo]uint16

	// numStackDeltaMapPages tracks the current size of the corresponding eBPF map.
	numStackDeltaMapPages uint64
}

// detectAndLoadInterpData attempts to detect the given executable as an interpreter. If detection
// succeeds, it then loads additional per-interpreter data into the BPF maps and returns the
// interpreter data.
func (state *executableInfoManagerState) detectAndLoadInterpData(
	loaderInfo *interpreter.LoaderInfo) interpreter.Data {
	// Ask all interpreter loaders whether they want to handle this executable.
	for _, loader := range state.interpreterLoaders {
		data, err := loader(state.ebpf, loaderInfo)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// Very common if the process exited when we tried to analyze it.
				log.Debugf("Failed to load %v (%#016x): file not found",
					loaderInfo.FileName(), loaderInfo.FileID())
			} else {
				log.Errorf("Failed to load %v (%#016x): %v",
					loaderInfo.FileName(), loaderInfo.FileID(), err)
			}
			return nil
		}
		if data == nil {
			continue
		}

		log.Debugf("Interpreter data %v for %v (%#016x)",
			data, loaderInfo.FileName(), loaderInfo.FileID())
		return data
	}

	return nil
}

// loadDeltas converts the sdtypes.StackDelta to StackDeltaEBPF and passes that to
// the ebpf interface to be loaded to kernel maps. While converting the deltas, it
// also creates a list of all large gaps in the executable.
func (state *executableInfoManagerState) loadDeltas(
	fileID host.FileID,
	deltas []sdtypes.StackDelta,
) (ref mapRef, gaps []util.Range, err error) {
	numDeltas := len(deltas)
	if numDeltas == 0 {
		// If no deltas are extracted, cache the result but don't reserve memory in BPF maps.
		return mapRef{MapID: 0}, []util.Range{}, nil
	}

	firstPage := deltas[0].Address >> support.StackDeltaPageBits
	firstPageAddr := deltas[0].Address &^ support.StackDeltaPageMask
	lastPage := deltas[numDeltas-1].Address >> support.StackDeltaPageBits
	numPages := lastPage - firstPage + 1
	numDeltasPerPage := make([]uint16, numPages)

	// Index the unwind-info.
	var unwindInfo sdtypes.UnwindInfo
	ebpfDeltas := make([]pmebpf.StackDeltaEBPF, 0, numDeltas)
	for index, delta := range deltas {
		if unwindInfo.MergeOpcode != 0 {
			// This delta was merged in the previous iteration.
			unwindInfo.MergeOpcode = 0
			continue
		}
		unwindInfo = delta.Info
		if index+1 < len(deltas) {
			unwindInfo.MergeOpcode = calculateMergeOpcode(delta, deltas[index+1])
			nextDeltaAddr := deltas[index+1].Address
			if delta.Hints&sdtypes.UnwindHintGap != 0 &&
				nextDeltaAddr-delta.Address >= minimumMemoizableGapSize {
				// Remember large gaps so ProcessManager plugins can
				// later use them to find precompiled blobs without deltas.
				gaps = append(gaps, util.Range{
					Start: delta.Address,
					End:   nextDeltaAddr})
			}
		}
		// Uses the new 'unwindInfo' with potentially updated MergeOpcode
		// here. In the end, it's only the unwindInfoIndex being different for
		// merged deltas.
		var unwindInfoIndex uint16
		unwindInfoIndex, err = state.getUnwindInfoIndex(unwindInfo)
		if err != nil {
			return mapRef{}, nil, err
		}
		ebpfDeltas = append(ebpfDeltas, pmebpf.StackDeltaEBPF{
			AddressLow: uint16(delta.Address),
			UnwindInfo: unwindInfoIndex,
		})
		numDeltasPerPage[(delta.Address>>support.StackDeltaPageBits)-firstPage]++
	}

	// Update data to eBPF
	mapID, err := state.ebpf.UpdateExeIDToStackDeltas(fileID, ebpfDeltas)
	if err != nil {
		return mapRef{}, nil,
			fmt.Errorf("failed UpdateExeIDToStackDeltas for FileID %x: %v", fileID, err)
	}

	// Update stack delta pages
	if err = state.ebpf.UpdateStackDeltaPages(fileID, numDeltasPerPage, mapID,
		firstPageAddr); err != nil {
		_ = state.ebpf.DeleteExeIDToStackDeltas(fileID, ref.MapID)
		return mapRef{}, nil,
			fmt.Errorf("failed UpdateStackDeltaPages for FileID %x: %v", fileID, err)
	}
	state.numStackDeltaMapPages += numPages

	return mapRef{
		MapID:     mapID,
		StartPage: firstPageAddr,
		NumPages:  uint32(numPages),
	}, gaps, nil
}

// calculateMergeOpcode calculates the merge opcode byte given two consecutive StackDeltas.
// Zero means no merging happened. Only small differences for address and the CFA delta
// are considered, in order to limit the amount of unique combinations generated.
func calculateMergeOpcode(delta, nextDelta sdtypes.StackDelta) uint8 {
	if delta.Info.Opcode == sdtypes.UnwindOpcodeCommand {
		return 0
	}
	addrDiff := nextDelta.Address - delta.Address
	if addrDiff < 1 || addrDiff > 2 {
		return 0
	}
	if nextDelta.Info.Opcode != delta.Info.Opcode ||
		nextDelta.Info.FPOpcode != delta.Info.FPOpcode ||
		nextDelta.Info.FPParam != delta.Info.FPParam {
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
	if info.Opcode == sdtypes.UnwindOpcodeCommand {
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
func (state *executableInfoManagerState) unloadDeltas(
	fileID host.FileID,
	ref *mapRef,
) error {
	if ref.MapID == 0 {
		// Nothing to do: no data was inserted in the first place.
		return nil
	}

	// To avoid race conditions first remove the stack delta page mappings
	// which reference the stack delta data.
	var err error
	for i := uint64(0); i < uint64(ref.NumPages); i++ {
		pageAddr := ref.StartPage + i<<support.StackDeltaPageBits
		err = errors.Join(err, state.ebpf.DeleteStackDeltaPage(fileID, pageAddr))
	}

	state.numStackDeltaMapPages -= uint64(ref.NumPages)

	// Now remove the actual stack delta data after all references are removed.
	return errors.Join(err, state.ebpf.DeleteExeIDToStackDeltas(fileID, ref.MapID))
}

// entry is the type used in the EIM executable map.
type entry struct {
	// ExecutableInfo is the public portion of the EIM entry.
	ExecutableInfo
	// mapRef stores info for identifying associated data in BPF maps.
	mapRef mapRef
	// rc determines in how many processes this executable is currently loaded.
	rc uint64
}

// mapRef stores all info required to identify and remove
// all data for an executable from our BPF maps.
type mapRef struct {
	StartPage uint64
	NumPages  uint32
	MapID     uint16
}
