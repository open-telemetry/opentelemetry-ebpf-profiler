// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"debug/elf"
	"errors"
	"fmt"
	"sort"

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

type FDE struct {
	PCBegin uint64
	PCRange uint64
}

type EhFrameTable struct {
	header         reader
	frames         reader
	fdeCount       uint64
	tableEntrySize int64
	tableEnc       encoding
	efm            elf.Machine

	// cieCache holds the CIEs decoded so far. This is the only piece that is
	// not concurrent safe, and could be made into a sync lru if needed.
	cieCache *lru.LRU[uint64, *cieInfo]
}

// NewEhFrameTable creates a new EhFrameTable from the given pfelf.File.
// The returned EhFrameTable is not concurrent safe.
func NewEhFrameTable(ef *pfelf.File) (*EhFrameTable, error) {
	var es ehframeSections
	err := es.locateSections(ef)
	if err != nil {
		return nil, fmt.Errorf("failed to get EH sections: %w", err)
	}
	if !es.header.isValid() {
		return nil, errors.New(".eh_frame_hdr not found")
	}
	if !es.frames.isValid() {
		return nil, errors.New(".eh_frame not found")
	}
	return newEhFrameTableFromSections(&es, ef.Machine)
}

// LookupIndex performs a binary search in .eh_frame_hdr for an FDE covering the given addr.
func (e *EhFrameTable) LookupIndex(addr libpf.Address) (int, error) {
	idx := sort.Search(e.count(), func(idx int) bool {
		r := e.entryAt(idx)
		ipStart, _ := r.ptr(e.tableEnc) // ignoring error, check bounds later
		return ipStart > uint64(addr)
	})
	if idx <= 0 {
		return -1, errors.New("FDE not found")
	}
	return idx - 1, nil
}

// DecodeIndex decodes an FDE based on the search table index.
func (e *EhFrameTable) DecodeIndex(idx int) (FDE, error) {
	ipStart, fr, entryErr := e.decodeEntryAt(idx)
	if entryErr != nil {
		return FDE{}, entryErr
	}
	_, fde, _, err := parsesFDEHeader(&fr, e.efm, ipStart, e.cieCache)
	if err != nil {
		return FDE{}, err
	}
	return FDE{
		PCBegin: fde.ipStart,
		PCRange: fde.ipLen,
	}, nil
}

// LookupFDE performs a binary search in .eh_frame_hdr for an FDE covering the given addr.
func (e *EhFrameTable) LookupFDE(addr libpf.Address) (FDE, error) {
	idx, err := e.LookupIndex(addr)
	if err != nil {
		return FDE{}, err
	}
	fde, err := e.DecodeIndex(idx)
	if err != nil {
		return FDE{}, err
	}
	if uint64(addr) < fde.PCBegin || uint64(addr) >= fde.PCBegin+fde.PCRange {
		return FDE{}, errors.New("FDE not found")
	}
	return fde, nil
}

func newEhFrameTableFromSections(es *ehframeSections, efm elf.Machine) (*EhFrameTable, error) {
	cieCache, err := lru.New[uint64, *cieInfo](cieCacheSize, hashUint64)
	if err != nil {
		return nil, err
	}
	return &EhFrameTable{
		fdeCount:       es.fdeCount,
		tableEntrySize: int64(formatLen(es.ehHdr.tableEnc)) * 2,
		tableEnc:       es.ehHdr.tableEnc,
		header:         es.header,
		frames:         es.frames,
		efm:            efm,
		cieCache:       cieCache,
	}, nil
}

// returns FDE count
func (e *EhFrameTable) count() int {
	return int(e.fdeCount)
}

// entryAt returns a reader for the binary search table at given index.
func (e *EhFrameTable) entryAt(idx int) reader {
	return e.header.offset(e.tableEntrySize * int64(idx))
}

// decodeEntry decodes one entry of the binary search table from the reader.
func (e *EhFrameTable) decodeEntry(r *reader) (ipStart uint64, fr reader, err error) {
	ipStart, err = r.ptr(e.tableEnc)
	if err != nil {
		return 0, reader{}, err
	}
	var fdeAddr uint64
	fdeAddr, err = r.ptr(e.tableEnc)
	if err != nil {
		return 0, reader{}, err
	}
	if fdeAddr < e.frames.vaddr {
		return 0, reader{}, fmt.Errorf("FDE %#x before section start %#x",
			fdeAddr, e.frames.vaddr)
	}
	fr = e.frames.offset(int64(fdeAddr - e.frames.vaddr))
	return ipStart, fr, err
}

// decodeEntryAt decodes the entry from given index.
func (e *EhFrameTable) decodeEntryAt(idx int) (ipStart uint64, fr reader, err error) {
	r := e.entryAt(idx)
	return e.decodeEntry(&r)
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
