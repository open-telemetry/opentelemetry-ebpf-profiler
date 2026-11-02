// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package execinfomanager

import (
	"errors"
	"sync"
	"testing"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/host"
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

// recordingEbpf records the map updates loadDeltas performs. The embedded interface is nil,
// so that an unexpected call panics, and every method takes mu for the concurrent test.
type recordingEbpf struct {
	pmebpf.EbpfHandler

	mu sync.Mutex

	deltas   []pmebpf.StackDeltaEBPF
	pages    []pmebpf.StackDeltaPage
	prefixes []lpm.Prefix
	fpInfo   uint16

	// fpRangeErr is returned by UpdateStackDeltaFPRanges, with fpRangeLeftover as what its
	// rollback left in the trie. unix.ENOSPC exercises the fallback, anything else the load.
	fpRangeErr      error
	fpRangeLeftover []lpm.Prefix
	// liveRanges, when non-nil, holds the prefixes still in the trie, so that a retried
	// delete reports what it really removed. Nil means every prefix is live.
	liveRanges map[lpm.Prefix]libpf.Void
	// fpRangeDeleteErr fails DeleteStackDeltaFPRanges, like a delete pass that stops.
	fpRangeDeleteErr error
	// pageDeleteErr fails the delete of the pages it lists.
	pageDeleteErr map[uint64]error
	// pageUpdateErr fails the pageUpdateErrOn'th UpdateStackDeltaPages call, counted from
	// one, which is how a load is made to fail at the hash map.
	pageUpdateErr   error
	pageUpdateErrOn int
	pageUpdateCalls int

	// deletedPages is what the teardowns removed from stack_delta_page_to_info.
	deletedPages []uint64
}

func (r *recordingEbpf) UpdateUnwindInfo(uint16, sdtypes.UnwindInfo) error {
	return nil
}

// setPageDeleteErr injects or clears the failure of the delete of pageAddr.
func (r *recordingEbpf) setPageDeleteErr(pageAddr uint64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err == nil {
		delete(r.pageDeleteErr, pageAddr)
		return
	}
	if r.pageDeleteErr == nil {
		r.pageDeleteErr = make(map[uint64]error)
	}
	r.pageDeleteErr[pageAddr] = err
}

func (r *recordingEbpf) UpdateExeIDToStackDeltas(_ host.FileID,
	deltas []pmebpf.StackDeltaEBPF,
) (uint16, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.deltas = deltas
	return support.StackDeltaBucketSmallest, nil
}

func (r *recordingEbpf) UpdateStackDeltaPages(_ host.FileID, pages []pmebpf.StackDeltaPage,
	_ uint16,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pageUpdateCalls++
	if r.pageUpdateErr != nil && r.pageUpdateCalls == r.pageUpdateErrOn {
		return r.pageUpdateErr
	}
	r.pages = append(r.pages, pages...)
	return nil
}

func (r *recordingEbpf) DeleteStackDeltaPage(_ host.FileID, page uint64) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.pageDeleteErr[page]; err != nil {
		return err
	}
	r.deletedPages = append(r.deletedPages, page)
	return nil
}

func (r *recordingEbpf) DeleteExeIDToStackDeltas(host.FileID, uint16) error {
	return nil
}

func (r *recordingEbpf) UpdateStackDeltaFPRanges(_ host.FileID, prefixes []lpm.Prefix,
	unwindInfo uint16,
) ([]lpm.Prefix, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fpRangeErr != nil {
		return r.fpRangeLeftover, r.fpRangeErr
	}
	r.prefixes = prefixes
	r.fpInfo = unwindInfo
	if r.liveRanges != nil {
		for _, prefix := range prefixes {
			r.liveRanges[prefix] = libpf.Void{}
		}
	}
	return nil, nil
}

func (r *recordingEbpf) DeleteStackDeltaFPRanges(_ host.FileID, prefixes []lpm.Prefix) (
	[]lpm.Prefix, error,
) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var failed []lpm.Prefix
	for _, prefix := range prefixes {
		if _, live := r.liveRanges[prefix]; r.liveRanges != nil && !live {
			// Already gone. The real implementation reports a missing key as neither
			// deleted nor failed, so that a retry converges.
			continue
		}
		if r.fpRangeDeleteErr != nil {
			failed = append(failed, prefix)
			continue
		}
		delete(r.liveRanges, prefix)
	}
	if failed != nil {
		return failed, r.fpRangeDeleteErr
	}
	return nil, nil
}

func newTestState(ebpf *recordingEbpf) *executableInfoManagerState {
	return &executableInfoManagerState{
		ebpf:            ebpf,
		executables:     make(map[host.FileID]*entry),
		unwindInfoIndex: make(map[sdtypes.UnwindInfo]uint16),
	}
}

func page(n uint64) uint64 { return n << support.StackDeltaPageBits }

// fpBlock returns a frame-pointer block, the shape whose pages are omitted.
func fpBlock(start, end uint64) *sdtypes.BasicBlock {
	bb := &sdtypes.BasicBlock{Start: start, End: end}
	bb.Deltas.Add(0, sdtypes.UnwindInfoFramePointer)
	return bb
}

// cfaBlock returns a block with a stack-pointer based delta at each of the given offsets, so
// that the pages it touches keep their entry. The parameters are spread far enough apart that
// the conversion does not merge the deltas away.
func cfaBlock(start, end uint64, offsets ...uint32) *sdtypes.BasicBlock {
	bb := &sdtypes.BasicBlock{Start: start, End: end}
	for i, offset := range offsets {
		bb.Deltas.Add(offset, sdtypes.UnwindInfo{
			BaseReg: support.UnwindRegSp,
			Param:   8 + int32(i)*0x38,
		})
	}
	return bb
}

// loadDeltasCase describes a loadDeltas run and everything it has to leave in the BPF maps,
// exhaustively, so that a case moving a page between the schemes fails wherever it does so.
type loadDeltasCase struct {
	// blocks is what the stack delta provider hands to loadDeltas.
	blocks []*sdtypes.BasicBlock
	// wantPages and wantPrefixes are the complete content of the two maps, wantDeltas the
	// length of the delta array the page entries index into.
	wantPages    []pmebpf.StackDeltaPage
	wantPrefixes []lpm.Prefix
	wantDeltas   int
}

// run drives one case against the map content. The mapRef has to name exactly what was
// inserted, as the teardown has nothing else to go by, and the counters have to follow it.
func (tc *loadDeltasCase) run(t *testing.T) {
	t.Helper()

	// NumDeltas counts the deltas before addDelta filters them, as the providers do.
	var numDeltas uint32
	for _, bb := range tc.blocks {
		numDeltas += uint32(len(bb.Deltas))
	}

	ebpf := &recordingEbpf{}
	state := newTestState(ebpf)

	ref, err := state.loadDeltas(host.FileID(0x1234),
		&sdtypes.IntervalData{NumDeltas: numDeltas, Blocks: tc.blocks})
	require.NoError(t, err)

	// FirstDelta indexes the omitted pages too, so the array length is part of this.
	assert.Equal(t, tc.wantPages, ebpf.pages)
	assert.Equal(t, tc.wantPrefixes, ebpf.prefixes)
	assert.Len(t, ebpf.deltas, tc.wantDeltas)

	var wantRefPages []uint64
	for _, p := range tc.wantPages {
		wantRefPages = append(wantRefPages, p.PageAddr)
	}
	assert.Equal(t, wantRefPages, ref.Pages)
	assert.Equal(t, tc.wantPrefixes, ref.FPPrefixes)
	assert.Equal(t, uint64(len(tc.wantPages)), state.numStackDeltaMapPages)
	assert.Equal(t, uint64(len(tc.wantPrefixes)), state.numStackDeltaFPRanges)

	assert.Equal(t, uint16(support.StackDeltaBucketSmallest), ref.MapID)
	if len(tc.wantPrefixes) > 0 {
		assert.Equal(t, support.DeltaCommandFlag|uint16(support.UnwindCommandFramePointer),
			ebpf.fpInfo)
	}

	// The invariant that makes the two lookups in get_stack_delta() safe to do
	// non-atomically. A range may only answer for a page that has no hash entry.
	for _, pageAddr := range ref.Pages {
		pageNum := pageAddr >> support.StackDeltaPageBits
		for _, prefix := range ebpf.prefixes {
			assert.False(t, coversPage(prefix, pageNum),
				"page %d keeps a hash entry, so no range may cover it", pageNum)
		}
	}
}

// TestLoadDeltas covers which pages of an executable keep a stack_delta_page_to_info entry
// and which are covered by a frame-pointer range instead.
func TestLoadDeltas(t *testing.T) {
	for name, tc := range map[string]loadDeltasCase{
		// Two frame-pointer spans with a small non-frame-pointer block wedged into the
		// first, the Go assembly islands of real Go executables, and a wide hole before
		// a third span. All 17 pages would be inserted without the range map. An entry
		// is kept by the pages holding a delta and the ones in the hole.
		"omitsFramePointerPages": {
			blocks: []*sdtypes.BasicBlock{
				fpBlock(page(1), page(5)),
				cfaBlock(page(5), page(5)+0x100, 0, 0x80),
				fpBlock(page(5)+0x100, page(9)),
				fpBlock(page(13), page(17)),
			},
			wantPages: []pmebpf.StackDeltaPage{
				{PageAddr: page(1), FirstDelta: 0, NumDeltas: 1},
				{PageAddr: page(5), FirstDelta: 1, NumDeltas: 3},
				{PageAddr: page(9), FirstDelta: 4, NumDeltas: 1},
				{PageAddr: page(10), FirstDelta: 5, NumDeltas: 0},
				{PageAddr: page(11), FirstDelta: 5, NumDeltas: 0},
				{PageAddr: page(12), FirstDelta: 5, NumDeltas: 0},
				{PageAddr: page(13), FirstDelta: 5, NumDeltas: 1},
				{PageAddr: page(17), FirstDelta: 6, NumDeltas: 1},
			},
			wantPrefixes: []lpm.Prefix{
				{Key: 2, Length: 63},
				{Key: 4, Length: 64},
				{Key: 6, Length: 63},
				{Key: 8, Length: 64},
				{Key: 14, Length: 63},
				{Key: 16, Length: 64},
			},
			wantDeltas: 7,
		},
	} {
		t.Run(name, func(t *testing.T) {
			tc.run(t)
		})
	}
}

// fakeSDP hands out fixed intervals, so that AddOrIncRef runs without a real executable.
type fakeSDP struct {
	intervals *sdtypes.IntervalData
}

func (f *fakeSDP) GetIntervalDataForFile(*pfelf.Reference) (*sdtypes.IntervalData, error) {
	return f.intervals, nil
}

func (f *fakeSDP) GetAndResetStatistics() nativeunwind.Statistics {
	return nativeunwind.Statistics{}
}

func newTestManager(t *testing.T, ebpf *recordingEbpf,
	intervals *sdtypes.IntervalData,
) *ExecutableInfoManager {
	t.Helper()
	deferredFileIDs, err := lru.NewSynced[host.FileID, libpf.Void](16,
		func(id host.FileID) uint32 { return uint32(id) })
	require.NoError(t, err)

	return &ExecutableInfoManager{
		sdp: &fakeSDP{intervals: intervals},
		state: xsync.NewRWMutex(executableInfoManagerState{
			ebpf:              ebpf,
			executables:       map[host.FileID]*entry{},
			unusedExecutables: map[host.FileID]time.Time{},
			unwindInfoIndex:   map[sdtypes.UnwindInfo]uint16{},
		}),
		deferredFileIDs: deferredFileIDs,
	}
}

// fpSpanIntervals returns a single whole-block frame-pointer span, the shape that leaves
// pages out of stack_delta_page_to_info.
func fpSpanIntervals() *sdtypes.IntervalData {
	fp := &sdtypes.BasicBlock{Start: page(1), End: page(5)}
	fp.Deltas.Add(0, sdtypes.UnwindInfoFramePointer)
	return &sdtypes.IntervalData{NumDeltas: 1, Blocks: []*sdtypes.BasicBlock{fp}}
}

// TestAddOrIncRefAfterFailedUnload covers that an executable whose teardown did not finish is
// not handed back as is. The file ID is refused and deferred while the retry keeps failing,
// and once the delete recovers the teardown finishes and the executable is loaded again.
func TestAddOrIncRefAfterFailedUnload(t *testing.T) {
	fileID := host.FileID(0x1234)
	elfRef := pfelf.NewReference("/tmp/does-not-need-to-exist", nil)

	ebpf := &recordingEbpf{
		pageDeleteErr: map[uint64]error{page(5): errors.New("deadlock")},
	}
	mgr := newTestManager(t, ebpf, fpSpanIntervals())
	summary := metrics.Summary{}

	// A cleanup pass whose page delete fails is what leaves the executable half unloaded.
	_, err := mgr.AddOrIncRef(fileID, elfRef)
	require.NoError(t, err)
	mgr.UpdateMetricSummary(summary)
	assert.Equal(t, metrics.MetricValue(1), summary[metrics.IDNumExeIDLoadedToEBPF])
	require.NoError(t, mgr.DecRef(fileID))
	require.Error(t, mgr.CleanupUnused(0))

	ebpf.pages, ebpf.prefixes = nil, nil
	_, err = mgr.AddOrIncRef(fileID, elfRef)
	require.Error(t, err)
	assert.Empty(t, ebpf.pages, "nothing may be loaded while the old state is still there")

	state := mgr.state.WLock()
	info, ok := state.executables[fileID]
	require.True(t, ok, "the entry has to stay for a later teardown retry")
	require.True(t, info.unloadFailed)
	assert.Zero(t, info.rc, "a refused executable must not hold a reference")
	// The ranges go first, so they are gone while the stuck page still covers text.
	assert.Empty(t, info.mapRef.FPPrefixes)
	assert.Equal(t, []uint64{page(5)}, info.mapRef.Pages)
	mgr.state.WUnlock(&state)

	// An entry that exists for the retry alone is no longer a loaded executable.
	mgr.UpdateMetricSummary(summary)
	assert.Equal(t, metrics.MetricValue(0), summary[metrics.IDNumExeIDLoadedToEBPF])
	assert.Equal(t, metrics.MetricValue(1), summary[metrics.IDHashmapNumStackDeltaPages])

	// The file ID is deferred, so the next mapping does not retry the same teardown.
	_, err = mgr.AddOrIncRef(fileID, elfRef)
	require.ErrorIs(t, err, ErrDeferredFileID)
	mgr.deferredFileIDs.Remove(fileID)

	ebpf.setPageDeleteErr(page(5), nil)
	_, err = mgr.AddOrIncRef(fileID, elfRef)
	require.NoError(t, err)

	// Everything is back, and the reloaded entry is a fresh one.
	state = mgr.state.WLock()
	info, ok = state.executables[fileID]
	require.True(t, ok)
	assert.False(t, info.unloadFailed)
	assert.Zero(t, state.numUnloadFailed)
	assert.Equal(t, uint64(1), info.rc)
	assert.Equal(t, []uint64{page(1), page(5)}, info.mapRef.Pages)
	assert.NotEmpty(t, info.mapRef.FPPrefixes)
	assert.NotContains(t, state.unusedExecutables, fileID)
	mgr.state.WUnlock(&state)
}

// doubleFailureEbpf returns a fake whose trie update fails with a prefix left behind and
// whose page insertion of the fallback then fails as well.
func doubleFailureEbpf(leftover []lpm.Prefix) *recordingEbpf {
	return &recordingEbpf{
		liveRanges:      map[lpm.Prefix]libpf.Void{leftover[0]: {}},
		fpRangeErr:      unix.ENOSPC,
		fpRangeLeftover: leftover,
		pageUpdateErr:   errors.New("map full"),
		pageUpdateErrOn: 1,
	}
}

// TestAddOrIncRefRecordsUnreclaimedLoad covers that the keys a failed load cannot reclaim
// stay on record instead of leaking, and that a later pass reclaims them.
func TestAddOrIncRefRecordsUnreclaimedLoad(t *testing.T) {
	fileID := host.FileID(0x1234)
	elfRef := pfelf.NewReference("/tmp/does-not-need-to-exist", nil)

	leftover := []lpm.Prefix{{Key: 2, Length: 63}}
	ebpf := doubleFailureEbpf(leftover)
	ebpf.fpRangeDeleteErr = errors.New("deadlock")
	mgr := newTestManager(t, ebpf, fpSpanIntervals())

	_, err := mgr.AddOrIncRef(fileID, elfRef)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to roll back the load")

	state := mgr.state.WLock()
	info, ok := state.executables[fileID]
	require.True(t, ok, "the leftovers have to stay on record")
	assert.True(t, info.unloadFailed)
	assert.Zero(t, info.rc, "a failed load must not hold a reference")
	// The prefix that could not be deleted does not hold back the pages, so those are gone
	// from the record and the gauge, while ref.MapID stays for the retry.
	assert.Equal(t, uint16(support.StackDeltaBucketSmallest), info.mapRef.MapID)
	assert.Equal(t, leftover, info.mapRef.FPPrefixes)
	assert.Empty(t, info.mapRef.Pages)
	assert.Len(t, ebpf.deletedPages, 5)
	assert.Zero(t, state.numStackDeltaMapPages)
	assert.Equal(t, uint64(1), state.numStackDeltaFPRanges)
	assert.Contains(t, state.unusedExecutables, fileID)
	mgr.state.WUnlock(&state)

	ebpf.fpRangeDeleteErr = nil
	require.NoError(t, mgr.CleanupUnused(0))

	state = mgr.state.WLock()
	assert.Empty(t, state.executables)
	assert.Empty(t, state.unusedExecutables)
	assert.Zero(t, state.numStackDeltaMapPages)
	assert.Zero(t, state.numStackDeltaFPRanges)
	mgr.state.WUnlock(&state)
}

// coversPage reports whether prefix matches the given stack delta page number, the way the
// kernel's LPM trie would.
func coversPage(prefix lpm.Prefix, pageNum uint64) bool {
	if prefix.Length == 0 {
		return true
	}
	return pageNum >= prefix.Key && pageNum-prefix.Key < uint64(1)<<(64-prefix.Length)
}

// TestCleanupUnusedSurvivesBadEntries covers that a pass reports a bookkeeping inconsistency
// or an unfinished teardown without aborting, keeps the executable whose keys are still in
// the maps, drops the inconsistent records and reclaims the healthy entries behind them.
func TestCleanupUnusedSurvivesBadEntries(t *testing.T) {
	const (
		dangling = host.FileID(0x1111) // queued as unused without an entry
		inUse    = host.FileID(0x2222) // queued as unused while still referenced
		failing  = host.FileID(0x3333) // teardown leaves a page behind
		healthy  = host.FileID(0x4444)
	)

	ebpf := &recordingEbpf{
		pageDeleteErr: map[uint64]error{page(5): errors.New("deadlock")},
	}
	unused := time.Now().Add(-time.Hour)
	state := executableInfoManagerState{
		ebpf:            ebpf,
		executables:     make(map[host.FileID]*entry),
		unwindInfoIndex: make(map[sdtypes.UnwindInfo]uint16),
		unusedExecutables: map[host.FileID]time.Time{
			dangling: unused, inUse: unused, failing: unused, healthy: unused,
		},
		numStackDeltaMapPages: 4,
	}
	loaded := func(rc uint64, pages ...uint64) *entry {
		return &entry{rc: rc, mapRef: mapRef{
			MapID: support.StackDeltaBucketSmallest,
			Pages: pages,
		}}
	}
	state.executables[inUse] = loaded(2, page(1))
	state.executables[failing] = loaded(0, page(5), page(7))
	state.executables[healthy] = loaded(0, page(9))

	mgr := &ExecutableInfoManager{state: xsync.NewRWMutex(state)}

	err := mgr.CleanupUnused(time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not in state.executables")
	assert.Contains(t, err.Error(), "when zero is expected")
	assert.Contains(t, err.Error(), "from BPF maps")

	locked := mgr.state.WLock()
	// The map iteration order is random, so an aborting pass would leave the healthy
	// executable behind at least sometimes.
	assert.NotContains(t, locked.executables, healthy)
	assert.Equal(t, uint64(2), locked.executables[inUse].rc)
	assert.Equal(t, []uint64{page(1)}, locked.executables[inUse].mapRef.Pages)
	assert.Equal(t, map[host.FileID]time.Time{failing: unused}, locked.unusedExecutables)

	// The mapRef of the stuck entry holds what the retry has to redo.
	info, ok := locked.executables[failing]
	require.True(t, ok, "the executable with leftover entries must be kept")
	assert.True(t, info.unloadFailed)
	assert.Equal(t, []uint64{page(5)}, info.mapRef.Pages)
	assert.Equal(t, uint64(2), locked.numStackDeltaMapPages)
	mgr.state.WUnlock(&locked)

	ebpf.setPageDeleteErr(page(5), nil)
	require.NoError(t, mgr.CleanupUnused(time.Minute))

	locked = mgr.state.WLock()
	assert.Len(t, locked.executables, 1)
	assert.Contains(t, locked.executables, inUse)
	assert.Empty(t, locked.unusedExecutables)
	assert.Zero(t, locked.numUnloadFailed)
	assert.Equal(t, uint64(1), locked.numStackDeltaMapPages)
	mgr.state.WUnlock(&locked)
}

// TestConcurrentAddOrIncRefAndCleanup drives the manager from several goroutines with a page
// delete that keeps failing, so that a load and a teardown overlap. Run with -race, it covers
// that the retry inside AddOrIncRef never hands out a half unloaded entry.
func TestConcurrentAddOrIncRefAndCleanup(t *testing.T) {
	const (
		workers = 8
		rounds  = 64
		files   = 16
	)

	// fpSpanIntervals loads the pages 1 and 5, so every teardown fails on its last one.
	ebpf := &recordingEbpf{}
	ebpf.setPageDeleteErr(page(5), errors.New("deadlock"))
	mgr := newTestManager(t, ebpf, fpSpanIntervals())
	elfRef := pfelf.NewReference("/tmp/does-not-need-to-exist", nil)

	var wg sync.WaitGroup
	for w := range workers {
		wg.Go(func() {
			for i := range rounds {
				fileID := host.FileID((w*rounds + i) % files)
				if _, err := mgr.AddOrIncRef(fileID, elfRef); err != nil {
					continue
				}
				// Every reference is given back, so the entries end at rc 0.
				assert.NoError(t, mgr.DecRef(fileID))
			}
		})
	}

	// The only failure a correctly locked run produces is the page delete.
	wg.Go(func() {
		for range workers * rounds {
			err := mgr.CleanupUnused(0)
			if err == nil {
				continue
			}
			assert.NotContains(t, err.Error(), "not in state.executables")
			assert.NotContains(t, err.Error(), "when zero is expected")
		}
	})
	wg.Wait()

	state := mgr.state.WLock()
	for fileID, info := range state.executables {
		assert.Zero(t, info.rc)
		assert.Contains(t, state.unusedExecutables, fileID,
			"fileID 0x%x has to be queued for the cleanup", fileID)
	}
	mgr.state.WUnlock(&state)

}
