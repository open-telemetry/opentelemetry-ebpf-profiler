// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"debug/elf"
	"errors"
	"fmt"
	"sort"
	"unsafe"

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

type FDE struct {
	PCBegin uintptr
	PCRange uintptr
}

type EhFrameTable struct {
	r             reader
	hdr           *ehFrameHdr
	fdeCount      uintptr
	tableStartPos uintptr
	ehFrameSec    *elfRegion
	efm           elf.Machine
	cieCache      *lru.LRU[uint64, *cieInfo]
}

// NewEhFrameTable creates a new EhFrameTable from the given pfelf.File
// The returned EhFrameTable must not be used concurrently
func NewEhFrameTable(ef *pfelf.File) (*EhFrameTable, error) {
	ehFrameHdrSec, ehFrameSec, err := findEhSections(ef)
	if err != nil {
		return nil, fmt.Errorf("failed to get EH sections: %w", err)
	}
	if ehFrameSec == nil {
		return nil, errors.New(".eh_frame not found")
	}
	if ehFrameHdrSec == nil {
		return nil, errors.New(".eh_frame_hdr not found")
	}
	return newEhFrameTableFromSections(ehFrameHdrSec, ehFrameSec, ef.Machine)
}

// LookupFDE performs a binary search in .eh_frame_hdr for an FDE covering the given addr.
func (e *EhFrameTable) LookupFDE(addr libpf.Address) (FDE, error) {
	idx := sort.Search(e.count(), func(idx int) bool {
		e.position(idx)
		ipStart, _, _ := e.parseHdrEntry() // ignoring error, check bounds later
		return ipStart > uintptr(addr)
	})
	if idx <= 0 {
		return FDE{}, errors.New("FDE not found")
	}
	e.position(idx - 1)
	ipStart, fr, entryErr := e.parseHdrEntry()
	if entryErr != nil {
		return FDE{}, entryErr
	}
	_, fde, _, err := parsesFDEHeader(&fr, e.efm, ipStart, e.cieCache)
	if err != nil {
		return FDE{}, err
	}
	if uintptr(addr) < fde.ipStart || uintptr(addr) >= fde.ipStart+fde.ipLen {
		return FDE{}, errors.New("FDE not found")
	}

	return FDE{
		PCBegin: fde.ipStart,
		PCRange: fde.ipLen,
	}, nil
}

func newEhFrameTableFromSections(ehFrameHdrSec *elfRegion,
	ehFrameSec *elfRegion, efm elf.Machine,
) (hp *EhFrameTable, err error) {
	hp = &EhFrameTable{
		hdr: (*ehFrameHdr)(unsafe.Pointer(&ehFrameHdrSec.data[0])),
		r:   ehFrameHdrSec.reader(unsafe.Sizeof(ehFrameHdr{}), false),
	}
	if _, err = hp.r.ptr(hp.hdr.ehFramePtrEnc); err != nil {
		return hp, err
	}
	if hp.fdeCount, err = hp.r.ptr(hp.hdr.fdeCountEnc); err != nil {
		return hp, err
	}
	if hp.cieCache, err = lru.New[uint64, *cieInfo](cieCacheSize, hashUint64); err != nil {
		return hp, err
	}
	hp.ehFrameSec = ehFrameSec
	hp.tableStartPos = hp.r.pos
	hp.efm = efm
	return hp, nil
}

// returns FDE count
func (e *EhFrameTable) count() int {
	return int(e.fdeCount)
}

// position adjusts the reader position to point at the table entry with idx index
func (e *EhFrameTable) position(idx int) {
	tableEntrySize := formatLen(e.hdr.tableEnc) * 2
	e.r.pos = e.tableStartPos + uintptr(tableEntrySize*idx)
}

// parseHdrEntry parsers an entry in the .eh_frame_hdr binary search table and the corresponding
// entry in the .eh_frame section
func (e *EhFrameTable) parseHdrEntry() (ipStart uintptr, fr reader, err error) {
	ipStart, err = e.r.ptr(e.hdr.tableEnc)
	if err != nil {
		return 0, reader{}, err
	}
	var fdeAddr uintptr
	fdeAddr, err = e.r.ptr(e.hdr.tableEnc)
	if err != nil {
		return 0, reader{}, err
	}
	if fdeAddr < e.ehFrameSec.vaddr {
		return 0, reader{}, fmt.Errorf("FDE %#x before section start %#x",
			fdeAddr, e.ehFrameSec.vaddr)
	}
	fr = e.ehFrameSec.reader(fdeAddr-e.ehFrameSec.vaddr, false)

	return ipStart, fr, err
}

// formatLen returns the length of a field encoded with enc encoding.
func formatLen(enc encoding) int {
	switch enc & encFormatMask {
	case encFormatData2:
		return 2
	case encFormatData4:
		return 4
	case encFormatData8, encFormatNative:
		return 8
	default:
		return 0
	}
}
