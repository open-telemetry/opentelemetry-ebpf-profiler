// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stackdeltatypes // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"

import (
	"cmp"
	"fmt"
	"math"
	"slices"

	"go.opentelemetry.io/ebpf-profiler/support"
)

// MaxPageSpan caps the stack delta page span of one executable, as every allocation of
// StackDeltas is sized by it. It covers 4GB of text, far above any real executable.
const MaxPageSpan = 1 << 16

// StackDeltaEBPF is one entry of the array get_stack_delta() binary searches. Its unwind
// info holds from AddressLow up to the next entry.
type StackDeltaEBPF struct {
	AddressLow uint16
	UnwindInfo uint16
}

// StackDeltaPage indexes one page into that array. FirstDelta is a prefix sum over the whole
// span, so a page holding no delta resolves through FirstDelta - 1.
type StackDeltaPage struct {
	PageAddr   uint64
	FirstDelta uint32
	NumDeltas  uint16
}

// DroppedDeltas counts the deltas StackDeltas left out, by the reason they cannot be
// represented.
type DroppedDeltas struct {
	// OutOfSpan is the deltas with no page in the span to be counted on.
	OutOfSpan uint64
	// OverLimit is the deltas past what StackDeltaPage.NumDeltas counts on their page.
	OverLimit uint64
	// Descending is the deltas below their predecessor, which the search needs ascending.
	Descending uint64
}

// isSignalDelta reports a delta that goes one byte below its address, to match the return
// address fixup of the eBPF unwinder.
func isSignalDelta(info UnwindInfo) bool {
	return info.Flags&support.UnwindFlagCommand != 0 &&
		info.Param == support.UnwindCommandSignal
}

// clipBlock returns the part of a block covering [from, to), from being at or above Start,
// with the delta reaching into it moved to the start. A part with no delta is nil.
func clipBlock(block *BasicBlock, from, to uint64) *BasicBlock {
	// A cut past the uint32 of a delta offset is above every delta.
	if from >= to || from-block.Start > math.MaxUint32 {
		return nil
	}
	index, exact := slices.BinarySearchFunc(block.Deltas, uint32(from-block.Start),
		func(delta StackDelta, offset uint32) int {
			return cmp.Compare(delta.Offset, offset)
		})
	if !exact && index > 0 {
		// The delta below the cut describes the start of the part.
		index--
	}

	clipped := &BasicBlock{Start: from, End: to}
	for _, delta := range block.Deltas[index:] {
		addr := block.Start + uint64(delta.Offset)
		if addr >= to {
			break
		}
		clipped.Deltas.Add(uint32(max(addr, from)-from), delta.Info)
	}
	if len(clipped.Deltas) == 0 {
		return nil
	}
	return clipped
}

// disjointBlocks returns the blocks ascending by Start and with no two ranges overlapping.
// Nothing rejects a nested or partly overlapping FDE, whose deltas would all descend below
// the enclosing block and go. The block starting later takes what both cover and the one
// enclosing it resumes behind, while a block ending below its own start goes entirely.
func disjointBlocks(blocks []*BasicBlock) []*BasicBlock {
	ordered := true
	for i, block := range blocks {
		// Only the clipping below drops an inverted block, so it must not pass here
		// either. Its terminator would land below its start, inside a valid range.
		inverted := block.End < block.Start
		overlaps := i > 0 &&
			(block.Start < blocks[i-1].Start || block.Start < blocks[i-1].End)
		if inverted || overlaps {
			ordered = false
			break
		}
	}
	if ordered {
		return blocks
	}

	sorted := slices.Clone(blocks)
	slices.SortStableFunc(sorted, func(a, b *BasicBlock) int {
		if order := cmp.Compare(a.Start, b.Start); order != 0 {
			return order
		}
		// Of two blocks starting together the shorter one is the more specific.
		return cmp.Compare(b.End, a.End)
	})

	// openBlock is a block covering the current address and where its rest starts.
	type openBlock struct {
		block *BasicBlock
		from  uint64
	}
	var open []openBlock
	disjoint := make([]*BasicBlock, 0, len(sorted))
	emit := func(block *BasicBlock, from, to uint64) {
		if clipped := clipBlock(block, from, to); clipped != nil {
			disjoint = append(disjoint, clipped)
		}
	}
	// closeTop hands what follows the innermost part to the block enclosing it. A nested
	// block reaching past its parent leaves from above End, and the rest resumes there.
	closeTop := func() {
		top := open[len(open)-1]
		open = open[:len(open)-1]
		emit(top.block, top.from, top.block.End)
		if len(open) > 0 {
			enclosing := &open[len(open)-1]
			enclosing.from = max(enclosing.from, top.from, top.block.End)
		}
	}

	for _, block := range sorted {
		for len(open) > 0 && open[len(open)-1].block.End <= block.Start {
			closeTop()
		}
		if len(open) > 0 {
			// The block being opened takes over from here.
			enclosing := &open[len(open)-1]
			emit(enclosing.block, enclosing.from, block.Start)
			enclosing.from = block.Start
		}
		open = append(open, openBlock{block: block, from: block.Start})
	}
	for len(open) > 0 {
		closeTop()
	}

	return disjoint
}

// stackDeltaBuilder accumulates the array get_stack_delta() binary searches, together with
// the per page counts the page table is made of.
type stackDeltaBuilder struct {
	// index maps an unwind info to its eBPF array index and may allocate one.
	index func(UnwindInfo) (uint16, error)
	// firstPage and lastPage bound the span every allocation here is sized by.
	firstPage uint64
	lastPage  uint64

	deltas           []StackDeltaEBPF
	numDeltasPerPage []uint16
	// lastAddr is the address of the delta added last, as the search needs them ascending.
	lastAddr uint64
	// dropped counts what the array cannot hold.
	dropped DroppedDeltas
}

// newStackDeltaBuilder sizes a builder for the span of the blocks, which have to be
// disjoint and ascending by Start. A span too wide to allocate for is rejected.
func newStackDeltaBuilder(blocks []*BasicBlock, index func(UnwindInfo) (uint16, error)) (
	*stackDeltaBuilder, error,
) {
	firstBlock := blocks[0]
	// disjointBlocks leaves the blocks ascending, so the last End is the highest. The max
	// keeps the span sound all the same, as every allocation below is sized by it.
	lastEnd := firstBlock.End
	numDeltas := len(firstBlock.Deltas)
	for _, block := range blocks[1:] {
		lastEnd = max(lastEnd, block.End)
		numDeltas += len(block.Deltas)
	}

	// The fixup in addBlock takes the first delta of the first block one byte down, to the
	// page before it where Start is page aligned.
	spanStart := firstBlock.Start
	if first := firstBlock.Deltas; spanStart > 0 && len(first) > 0 && first[0].Offset == 0 &&
		isSignalDelta(first[0].Info) {
		spanStart--
	}

	firstPage := spanStart >> support.StackDeltaPageBits
	lastPage := max(lastEnd>>support.StackDeltaPageBits, firstPage)
	numPages := lastPage - firstPage + 1
	// Nothing checks an FDE address against the text segment, and one far above the others
	// stretches the span over billions of pages.
	if numPages > MaxPageSpan {
		return nil, fmt.Errorf(
			"stack delta span [%#x, %#x] covers %d pages, more than the %d supported",
			spanStart, lastEnd, numPages, MaxPageSpan)
	}

	return &stackDeltaBuilder{
		index:     index,
		firstPage: firstPage,
		lastPage:  lastPage,
		// Splitting an enclosing block repeats a delta, so NumDeltas no longer
		// counts them.
		deltas:           make([]StackDeltaEBPF, 0, numDeltas),
		numDeltasPerPage: make([]uint16, numPages),
	}, nil
}

// add appends the delta of one address, or counts it as dropped where the array cannot
// represent it.
func (b *stackDeltaBuilder) add(addr uint64, info UnwindInfo) error {
	// A delta outside the span has no page to be counted on. An inverted span collapses
	// to the first page, so a malformed .eh_frame drops many here.
	page := addr >> support.StackDeltaPageBits
	if page < b.firstPage || page > b.lastPage {
		b.dropped.OutOfSpan++
		return nil
	}
	// The blocks are disjoint, so only one with descending deltas of its own gets here.
	// Such a delta shifts the FirstDelta prefix sum of every page behind it and leaves
	// its own unsorted for the bsearch. Equal addresses stay.
	if addr < b.lastAddr {
		b.dropped.Descending++
		return nil
	}
	unwindInfoIndex, err := b.index(info)
	if err != nil {
		return err
	}
	// The previous delta already covers the addresses up to the next one, so the per page
	// limit below does not apply either. A merged info resolves by the distance from its
	// own delta, so it never stands for an earlier one.
	if num := len(b.deltas); num > 0 && info.MergeOpcode == 0 &&
		b.deltas[num-1].UnwindInfo == unwindInfoIndex {
		return nil
	}
	// A page holds one address more than NumDeltas counts. Wrapped to zero it would mean
	// 'no delta on this page', so the rest keeps the info of the last one.
	if b.numDeltasPerPage[page-b.firstPage] == math.MaxUint16 {
		b.dropped.OverLimit++
		return nil
	}
	b.deltas = append(b.deltas, StackDeltaEBPF{
		AddressLow: uint16(addr),
		UnwindInfo: unwindInfoIndex,
	})
	b.numDeltasPerPage[page-b.firstPage]++
	b.lastAddr = addr
	return nil
}

// addBlock appends the deltas of one block, merging the pairs that fit one opcode.
// terminate closes the block with an invalid info, so an address behind it reports no
// unwind info instead of resolving through the block below.
func (b *stackDeltaBuilder) addBlock(block *BasicBlock, terminate bool) error {
	var unwindInfo UnwindInfo
	for deltaIndex, delta := range block.Deltas {
		if unwindInfo.MergeOpcode != 0 {
			// This delta was merged in the previous iteration.
			unwindInfo.MergeOpcode = 0
			continue
		}
		unwindInfo = delta.Info
		if deltaIndex+1 < len(block.Deltas) {
			unwindInfo.MergeOpcode = mergeOpcode(delta, block.Deltas[deltaIndex+1])
		}

		addr := block.Start + uint64(delta.Offset)
		if isSignalDelta(unwindInfo) {
			// C libraries insert a 'nop' at the byte below, so that nothing
			// conflicts with the delta starting there.
			addr--
		}

		// The MergeOpcode is part of the info, so a merged pair indexes its own.
		if err := b.add(addr, unwindInfo); err != nil {
			return err
		}
	}
	if terminate {
		return b.add(block.End, UnwindInfoInvalid)
	}
	return nil
}

// pages returns the pages of the span resolving into the delta array, ascending.
func (b *stackDeltaBuilder) pages() []StackDeltaPage {
	// A page behind the last delta keeps its entry, as the span can reach over a block
	// whose terminator was dropped.
	pages := make([]StackDeltaPage, 0, len(b.numDeltasPerPage))
	firstDelta := uint32(0)
	for page, numDeltas := range b.numDeltasPerPage {
		if numDeltas == 0 && firstDelta == 0 {
			// Nothing to resolve through, and FirstDelta - 1 would wrap. Left out,
			// it reports the missing text section instead.
			continue
		}
		pages = append(pages, StackDeltaPage{
			PageAddr:   (b.firstPage + uint64(page)) << support.StackDeltaPageBits,
			FirstDelta: firstDelta,
			NumDeltas:  numDeltas,
		})
		firstDelta += uint32(numDeltas)
	}
	return pages
}

// StackDeltas converts the intervals into the array get_stack_delta() binary searches, with
// the pages of the span resolving into it, ascending. index maps an unwind info to its eBPF
// array index and may allocate one. What the array cannot hold is dropped and counted.
func (intervals *IntervalData) StackDeltas(index func(UnwindInfo) (uint16, error)) (
	[]StackDeltaEBPF, []StackDeltaPage, DroppedDeltas, error,
) {
	var dropped DroppedDeltas
	if intervals.NumDeltas == 0 {
		return nil, nil, dropped, nil
	}
	blocks := disjointBlocks(intervals.Blocks)
	if len(blocks) == 0 {
		return nil, nil, dropped, nil
	}

	builder, err := newStackDeltaBuilder(blocks, index)
	if err != nil {
		return nil, nil, dropped, err
	}
	for blockIndex, block := range blocks {
		gap := blockIndex+1 == len(blocks) ||
			block.End+MinimumGap < blocks[blockIndex+1].Start
		if err := builder.addBlock(block, gap); err != nil {
			return nil, nil, builder.dropped, err
		}
	}

	if len(builder.deltas) == 0 {
		// NumDeltas counts the deltas before the builder filtered. A page entry would
		// hold NumDeltas = 0 with nothing before it, wrapping FirstDelta - 1.
		return nil, nil, builder.dropped, nil
	}
	return builder.deltas, builder.pages(), builder.dropped, nil
}

// mergeOpcode calculates the merge opcode byte given two consecutive StackDeltas. Zero means
// no merging happened. Only small differences for address and the CFA delta are considered,
// in order to limit the amount of unique combinations generated.
func mergeOpcode(delta, nextDelta StackDelta) uint8 {
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
	switch nextDelta.Info.Param - delta.Info.Param {
	case 8:
		return uint8(addrDiff)
	case -8:
		return uint8(addrDiff) | support.MergeOpcodeNegative
	}
	return 0
}
