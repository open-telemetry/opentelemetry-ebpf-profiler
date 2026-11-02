// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stackdeltatypes

import (
	"errors"
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/support"
)

func page(n uint64) uint64 { return n << support.StackDeltaPageBits }

// cmdIndex is the direct encoding of a whole-block command.
func cmdIndex(param int32) uint16 {
	return support.DeltaCommandFlag | uint16(param)
}

// testIndex mirrors the unwind info index of the agent. A command is encoded directly, every
// other info is numbered as it is seen.
func testIndex() func(UnwindInfo) (uint16, error) {
	seen := make(map[UnwindInfo]uint16)
	return func(info UnwindInfo) (uint16, error) {
		if info.Flags&support.UnwindFlagCommand != 0 {
			return cmdIndex(info.Param), nil
		}
		if index, ok := seen[info]; ok {
			return index, nil
		}
		index := uint16(len(seen))
		seen[info] = index
		return index, nil
	}
}

// nonFPInfo returns an unwind info that is not a whole-block command.
func nonFPInfo(param int32) UnwindInfo {
	return UnwindInfo{BaseReg: support.UnwindRegSp, Param: param}
}

// cmdBlock returns a block carrying a single whole-block command at its start.
func cmdBlock(start, end uint64, info UnwindInfo) *BasicBlock {
	bb := &BasicBlock{Start: start, End: end}
	bb.Deltas.Add(0, info)
	return bb
}

// fpBlock returns a frame-pointer block, the shape a load leaves out of the hash map.
func fpBlock(start, end uint64) *BasicBlock {
	return cmdBlock(start, end, UnwindInfoFramePointer)
}

// cfaBlock returns a block with a stack-pointer based delta at each of the given offsets,
// spread far enough apart that mergeOpcode does not merge them away.
func cfaBlock(start, end uint64, offsets ...uint32) *BasicBlock {
	return cfaBlockFrom(start, end, 0, offsets...)
}

// cfaBlockFrom is cfaBlock with the unwind infos numbered from the given one, so the deltas
// of two blocks are told apart.
func cfaBlockFrom(start, end uint64, first int32, offsets ...uint32) *BasicBlock {
	bb := &BasicBlock{Start: start, End: end}
	for i, offset := range offsets {
		bb.Deltas.Add(offset, nonFPInfo(8+(first+int32(i))*0x38))
	}
	return bb
}

// stackDeltasCase describes one StackDeltas run and all it produces, exhaustively.
type stackDeltasCase struct {
	// blocks is what a provider hands over, in the order it does.
	blocks []*BasicBlock
	// wantNumDeltas is the length of the delta array, wantDeltas its content.
	wantNumDeltas int
	wantDeltas    []StackDeltaEBPF
	// wantPages is every page of the span that has to resolve, ascending.
	wantPages []StackDeltaPage
	// wantDropped is what the array cannot hold.
	wantDropped DroppedDeltas
	// wantErr is a substring of the error of a conversion that has to be rejected.
	wantErr string
}

func (tc *stackDeltasCase) run(t *testing.T) {
	t.Helper()

	// NumDeltas counts the deltas before StackDeltas filters them, as the providers do.
	var numDeltas uint32
	for _, bb := range tc.blocks {
		numDeltas += uint32(len(bb.Deltas))
	}
	intervals := &IntervalData{NumDeltas: numDeltas, Blocks: tc.blocks}

	// A block reaching outside the span must not index outside the per page bookkeeping.
	var deltas []StackDeltaEBPF
	var pages []StackDeltaPage
	var dropped DroppedDeltas
	var err error
	require.NotPanics(t, func() {
		deltas, pages, dropped, err = intervals.StackDeltas(testIndex())
	})
	if tc.wantErr != "" {
		require.Error(t, err)
		assert.Contains(t, err.Error(), tc.wantErr)
	} else {
		require.NoError(t, err)
	}

	assert.Len(t, deltas, tc.wantNumDeltas)
	if tc.wantDeltas != nil {
		assert.Equal(t, tc.wantDeltas, deltas)
	}
	assert.Equal(t, tc.wantPages, pages)
	assert.Equal(t, tc.wantDropped, dropped)

	// The bsearch needs the array ascending within a page, equal addresses aside.
	for _, p := range pages {
		for i := p.FirstDelta + 1; i < p.FirstDelta+uint32(p.NumDeltas); i++ {
			assert.LessOrEqual(t, deltas[i-1].AddressLow, deltas[i].AddressLow,
				"delta %d of page %#x descends", i, p.PageAddr)
		}
	}

	// FirstDelta is a prefix sum, so it has to run over the pages without a gap.
	for i := 1; i < len(pages); i++ {
		assert.Equal(t, pages[i-1].FirstDelta+uint32(pages[i-1].NumDeltas),
			pages[i].FirstDelta, "FirstDelta of page %#x", pages[i].PageAddr)
	}
	if last := len(pages) - 1; last >= 0 {
		assert.Equal(t, len(deltas),
			int(pages[last].FirstDelta)+int(pages[last].NumDeltas),
			"the page entries have to index the whole array")
	}
}

// TestStackDeltas covers the conversion of the intervals of an executable into the array
// get_stack_delta() searches and the pages indexing it.
func TestStackDeltas(t *testing.T) {
	fp := cmdIndex(support.UnwindCommandFramePointer)
	invalid := cmdIndex(support.UnwindCommandInvalid)

	// A page holding a delta on every address. The infos alternate and are 16 apart, so
	// that neither the dedup nor mergeOpcode collapses them.
	densePage := func() *BasicBlock {
		bb := &BasicBlock{Start: page(2), End: page(3)}
		for offset := range uint32(1 << support.StackDeltaPageBits) {
			bb.Deltas.Add(offset, nonFPInfo(8+int32(offset%2)*16))
		}
		return bb
	}

	for name, tc := range map[string]stackDeltasCase{
		// Two deltas a byte apart whose CFA differs by 8 merge into one entry.
		"mergesNeighbouringDeltas": {
			blocks: func() []*BasicBlock {
				bb := &BasicBlock{Start: page(1), End: page(2)}
				bb.Deltas.Add(0, nonFPInfo(8))
				bb.Deltas.Add(1, nonFPInfo(16))
				return []*BasicBlock{bb}
			}(),
			wantNumDeltas: 2,
			wantDeltas: []StackDeltaEBPF{
				{AddressLow: 0, UnwindInfo: 0},
				{AddressLow: 0, UnwindInfo: invalid},
			},
			wantPages: []StackDeltaPage{
				{PageAddr: page(1), FirstDelta: 0, NumDeltas: 1},
				{PageAddr: page(2), FirstDelta: 1, NumDeltas: 1},
			},
		},

		// A merged pair repeating later in the block. The dedup would drop the
		// second one, leaving the unwinder to measure the merge distance from the
		// first and hand out the raised CFA where the lower one holds.
		"keepsRepeatedMergedDelta": {
			blocks: func() []*BasicBlock {
				bb := &BasicBlock{Start: page(1), End: page(2)}
				bb.Deltas.Add(0, nonFPInfo(8))
				bb.Deltas.Add(1, nonFPInfo(16))
				bb.Deltas.Add(0x100, nonFPInfo(8))
				bb.Deltas.Add(0x101, nonFPInfo(16))
				return []*BasicBlock{bb}
			}(),
			wantNumDeltas: 3,
			wantDeltas: []StackDeltaEBPF{
				{AddressLow: 0, UnwindInfo: 0},
				{AddressLow: 0x100, UnwindInfo: 0},
				{AddressLow: 0, UnwindInfo: invalid},
			},
			wantPages: []StackDeltaPage{
				{PageAddr: page(1), FirstDelta: 0, NumDeltas: 2},
				{PageAddr: page(2), FirstDelta: 2, NumDeltas: 1},
			},
		},

		// A block nested in another, the shape two FDEs over the same code leave behind.
		// The enclosing block has to resume above it, or the inner addresses resolve
		// to the CFA of the outer function.
		"resolvesNestedBlock": {
			blocks: []*BasicBlock{
				cfaBlock(page(1), page(1)+0x400, 0, 0x300),
				cfaBlockFrom(page(1)+0x200, page(1)+0x280, 2, 0),
			},
			wantNumDeltas: 5,
			wantDeltas: []StackDeltaEBPF{
				{AddressLow: 0, UnwindInfo: 0},
				{AddressLow: 0x200, UnwindInfo: 1},
				{AddressLow: 0x280, UnwindInfo: 0},
				{AddressLow: 0x300, UnwindInfo: 2},
				{AddressLow: 0x400, UnwindInfo: invalid},
			},
			wantPages: []StackDeltaPage{
				{PageAddr: page(1), FirstDelta: 0, NumDeltas: 5},
			},
		},

		// A page covers one address more than the uint16 NumDeltas counts, so the last
		// delta goes rather than wrapping the count to 'no delta on this page'.
		"saturatesDensePage": {
			blocks:        []*BasicBlock{fpBlock(page(1), page(2)), densePage()},
			wantNumDeltas: 2 + math.MaxUint16,
			wantPages: []StackDeltaPage{
				{PageAddr: page(1), FirstDelta: 0, NumDeltas: 1},
				{PageAddr: page(2), FirstDelta: 1, NumDeltas: math.MaxUint16},
				{PageAddr: page(3), FirstDelta: 1 + math.MaxUint16, NumDeltas: 1},
			},
			wantDropped: DroppedDeltas{OverLimit: 1},
		},

		// An inverted block covers nothing, so nothing is left to convert. Its
		// terminator would otherwise land below its own start.
		"dropsSoleInvertedBlock": {
			blocks: []*BasicBlock{
				cfaBlock(page(4), page(1), uint32(page(1))),
			},
		},

		// A delta reaching above the block holding it has no page in the span to be
		// counted on. The span starts at a page with nothing to resolve through, which
		// is left out so a lookup reports the missing text section.
		"dropsDeltaAboveTheSpan": {
			blocks: []*BasicBlock{
				cfaBlock(page(1), page(2), uint32(page(5))),
			},
			wantNumDeltas: 1,
			wantDeltas: []StackDeltaEBPF{
				{AddressLow: 0, UnwindInfo: invalid},
			},
			wantPages: []StackDeltaPage{
				{PageAddr: page(2), FirstDelta: 0, NumDeltas: 1},
			},
			wantDropped: DroppedDeltas{OutOfSpan: 1},
		},

		// A page aligned signal trampoline as the lowest block. Its delta goes one byte
		// down for the eBPF fixup, so the span has to start a page below the block.
		"spansBelowAPageAlignedSignalBlock": {
			blocks: []*BasicBlock{
				cmdBlock(page(4), page(4)+0x10, UnwindInfoSignal),
				fpBlock(page(5), page(6)),
			},
			wantNumDeltas: 4,
			wantDeltas: []StackDeltaEBPF{
				{AddressLow: 0xffff, UnwindInfo: cmdIndex(support.UnwindCommandSignal)},
				{AddressLow: 0x10, UnwindInfo: invalid},
				{AddressLow: 0, UnwindInfo: fp},
				{AddressLow: 0, UnwindInfo: invalid},
			},
			wantPages: []StackDeltaPage{
				{PageAddr: page(3), FirstDelta: 0, NumDeltas: 1},
				{PageAddr: page(4), FirstDelta: 1, NumDeltas: 1},
				{PageAddr: page(5), FirstDelta: 2, NumDeltas: 1},
				{PageAddr: page(6), FirstDelta: 3, NumDeltas: 1},
			},
		},

		// A block with no delta of its own ends the span above the last delta, as the
		// dedup drops its terminator behind the one of the block below. The pages
		// between keep an entry, which resolves through the last delta.
		"keepsPagesBehindTheLastDelta": {
			blocks: []*BasicBlock{
				cfaBlock(page(1), page(2), 0),
				{Start: page(4), End: page(6)},
			},
			wantNumDeltas: 2,
			wantDeltas: []StackDeltaEBPF{
				{AddressLow: 0, UnwindInfo: 0},
				{AddressLow: 0, UnwindInfo: invalid},
			},
			wantPages: []StackDeltaPage{
				{PageAddr: page(1), FirstDelta: 0, NumDeltas: 1},
				{PageAddr: page(2), FirstDelta: 1, NumDeltas: 1},
				{PageAddr: page(3), FirstDelta: 2, NumDeltas: 0},
				{PageAddr: page(4), FirstDelta: 2, NumDeltas: 0},
				{PageAddr: page(5), FirstDelta: 2, NumDeltas: 0},
				{PageAddr: page(6), FirstDelta: 2, NumDeltas: 0},
			},
		},

		// A span wider than MaxPageSpan is rejected before anything is sized by it, the
		// shape a single bogus FDE near the top of the 47 bit space gives.
		"rejectsOversizedSpan": {
			blocks: []*BasicBlock{
				cfaBlock(page(1), page(2), 0),
				cfaBlock(1<<46, 1<<46+page(1), 0),
			},
			wantErr: "covers 1073741825 pages",
		},
	} {
		t.Run(name, func(t *testing.T) {
			tc.run(t)
		})
	}
}

// renderBlocks spells the blocks out as "[start,end) +offset=param ...".
func renderBlocks(blocks []*BasicBlock) []string {
	rendered := make([]string, 0, len(blocks))
	for _, block := range blocks {
		line := fmt.Sprintf("[%#x,%#x)", block.Start, block.End)
		for _, delta := range block.Deltas {
			line += fmt.Sprintf(" +%#x=%d", delta.Offset, delta.Info.Param)
		}
		rendered = append(rendered, line)
	}
	return rendered
}

// TestDisjointBlocks covers the overlap resolution the ascending delta array needs.
func TestDisjointBlocks(t *testing.T) {
	for name, tc := range map[string]struct {
		blocks []*BasicBlock
		want   []string
	}{
		// Sort() runs only with .eh_frame, so the blocks can arrive in any order.
		"ordersBlocksByStart": {
			blocks: []*BasicBlock{
				cfaBlockFrom(0x2000, 0x3000, 1, 0),
				cfaBlock(0x1000, 0x2000, 0),
			},
			want: []string{"[0x1000,0x2000) +0x0=8", "[0x2000,0x3000) +0x0=64"},
		},
		// Two FDEs reaching into each other, neither nested.
		"clipsPartialOverlap": {
			blocks: []*BasicBlock{
				cfaBlock(0x1000, 0x1300, 0),
				cfaBlockFrom(0x1200, 0x1400, 1, 0),
			},
			want: []string{"[0x1000,0x1200) +0x0=8", "[0x1200,0x1400) +0x0=64"},
		},
		// Neither block starts later, so the shorter one wins as the more specific.
		"prefersShorterBlockOnEqualStart": {
			blocks: []*BasicBlock{
				cfaBlock(0x1000, 0x1400, 0),
				cfaBlockFrom(0x1000, 0x1200, 1, 0),
			},
			want: []string{"[0x1000,0x1200) +0x0=64", "[0x1200,0x1400) +0x0=8"},
		},
		// Every block of the nest resumes where the one inside it ends.
		"nestsThreeDeep": {
			blocks: []*BasicBlock{
				cfaBlock(0x1000, 0x2000, 0),
				cfaBlockFrom(0x1100, 0x1f00, 1, 0),
				cfaBlockFrom(0x1200, 0x1300, 2, 0),
			},
			want: []string{
				"[0x1000,0x1100) +0x0=8", "[0x1100,0x1200) +0x0=64",
				"[0x1200,0x1300) +0x0=120", "[0x1300,0x1f00) +0x0=64",
				"[0x1f00,0x2000) +0x0=8",
			},
		},
		// A nested block reaching past its parent keeps what both cover, so the
		// grandparent has to resume behind the nested one, not behind the parent.
		"resumesBehindOverhangingBlock": {
			blocks: []*BasicBlock{
				cfaBlock(0x1000, 0x2000, 0),
				cfaBlockFrom(0x1100, 0x1400, 1, 0),
				cfaBlockFrom(0x1200, 0x1500, 2, 0),
			},
			want: []string{
				"[0x1000,0x1100) +0x0=8", "[0x1100,0x1200) +0x0=64",
				"[0x1200,0x1500) +0x0=120", "[0x1500,0x2000) +0x0=8",
			},
		},
		// A block ending below its own start covers nothing, and must not take the
		// addresses from the one enclosing it.
		"dropsInvertedBlock": {
			blocks: []*BasicBlock{
				cfaBlock(0x1000, 0x2000, 0),
				cfaBlockFrom(0x1200, 0x1100, 1, 0),
			},
			want: []string{"[0x1000,0x1200) +0x0=8", "[0x1200,0x2000) +0x0=8"},
		},
		// An inverted block starting at the end of the one before it overlaps nothing,
		// so only the inversion keeps it off the fast path.
		"dropsInvertedBlockInOrder": {
			blocks: []*BasicBlock{
				cfaBlock(0x1000, 0x2000, 0),
				cfaBlockFrom(0x2000, 0x1800, 1, 0),
			},
			want: []string{"[0x1000,0x2000) +0x0=8"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			disjoint := disjointBlocks(tc.blocks)
			assert.Equal(t, tc.want, renderBlocks(disjoint))

			// The conversion needs each delta above the one before it.
			for i := 1; i < len(disjoint); i++ {
				assert.GreaterOrEqual(t, disjoint[i].Start, disjoint[i-1].End,
					"block %d overlaps the one before it", i)
			}
		})
	}
}

// TestStackDeltasReportsIndexError covers that a failure to resolve an unwind info fails the
// conversion, as the delta would reference an index that was never loaded.
func TestStackDeltasReportsIndexError(t *testing.T) {
	errFull := errors.New("unwind info array is full")
	intervals := &IntervalData{
		NumDeltas: 1,
		Blocks:    []*BasicBlock{cfaBlock(page(1), page(2), 0)},
	}

	// Only the delta closing the block carries a command, so the conversion fails on it
	// after the delta of the block itself went through.
	_, _, _, err := intervals.StackDeltas(func(info UnwindInfo) (uint16, error) {
		if info.Flags&support.UnwindFlagCommand != 0 {
			return 0, errFull
		}
		return 0, nil
	})
	require.ErrorIs(t, err, errFull)
}
