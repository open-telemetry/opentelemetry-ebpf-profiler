// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"errors"
	"fmt"
	"unsafe"

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

type ehFrameTable struct {
	r             reader
	hdr           *ehFrameHdr
	fdeCount      uintptr
	tableStartPos uintptr
	ehFrameSec    *elfRegion
	cieCache      *lru.LRU[uint64, *cieInfo]
}

func newEhFrameTableFromSections(ehFrameHdrSec *elfRegion,
	ehFrameSec *elfRegion) (hp ehFrameTable, err error) {
	hp = ehFrameTable{
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

	return hp, nil
}

func newEhFrameTable(ef *pfelf.File) (ehFrameTable, error) {
	ehFrameHdrSec, ehFrameSec, err := findEhSections(ef)
	if err != nil {
		return ehFrameTable{}, fmt.Errorf("failed to get EH sections: %w", err)
	}
	if ehFrameSec == nil {
		return ehFrameTable{}, errors.New(".eh_frame not found")
	}
	if ehFrameHdrSec == nil {
		return ehFrameTable{}, errors.New(".eh_frame_hdr not found")
	}
	return newEhFrameTableFromSections(ehFrameHdrSec, ehFrameSec)
}

// returns FDE count
func (e *ehFrameTable) count() int {
	return int(e.fdeCount)
}

// position adjusts the reader position to point at the table entry with idx index
func (e *ehFrameTable) position(idx int) {
	tableEntrySize := formatLen(e.hdr.tableEnc) * 2
	e.r.pos = e.tableStartPos + uintptr(tableEntrySize*idx)
}

// parseHdrEntry parsers an entry in the .eh_frame_hdr binary search table and the corresponding
// entry in the .eh_frame section
func (e *ehFrameTable) parseHdrEntry() (ipStart uintptr, fr reader, err error) {
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
