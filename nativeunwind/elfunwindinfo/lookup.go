// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"errors"
	"fmt"
	"sort"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
)

// FDE
type FDE struct {
	Start uintptr
	End   uintptr
}

// LookupFDE performs a binary search in .eh_frame_hdr for an FDE covering the given addr.
func LookupFDE(ef *pfelf.File, addr uintptr) (FDE, error) {
	ehFrameHdrSec, ehFrameSec, err := findEhSections(ef)
	if err != nil {
		return FDE{}, fmt.Errorf("failed to get EH sections: %w", err)
	}
	if ehFrameSec == nil {
		return FDE{}, errors.New(".eh_frame not found")
	}
	if ehFrameHdrSec == nil {
		return FDE{}, errors.New(".eh_frame_hdr not found")
	}

	hook := lookupHook{}
	ee := elfExtractor{
		ref:              nil,
		file:             ef,
		hooks:            &hook,
		deltas:           nil,
		allowGenericRegs: false,
	}
	hp, err := ee.newHdrParser(ehFrameHdrSec)
	if err != nil {
		return FDE{}, nil
	}
	tableEntrySize := hp.r.formatLen(hp.hdr.tableEnc) * 2
	tableStartPos := hp.r.pos
	parseFDE := func(idx int) (fdeInfo, error) {
		hp.r.pos = tableStartPos + uintptr(tableEntrySize*idx)
		if entryErr := ee.parseHdrEntry(ef, &hp, ehFrameSec); entryErr != nil {
			return fdeInfo{}, entryErr
		}
		return hook.fde, nil
	}
	var fde fdeInfo
	idx := sort.Search(int(hp.fdeCount), func(idx int) bool {
		if err != nil {
			return false
		}
		fde, err = parseFDE(idx)
		if err != nil {
			return false
		}
		return fde.ipStart > addr
	})
	if err != nil {
		return FDE{}, err
	}
	idx--
	if idx < 0 {
		return FDE{}, errors.New("FDE not found")
	}
	fde, err = parseFDE(idx)
	if err != nil {
		return FDE{}, err
	}
	if addr < fde.ipStart || addr >= fde.ipStart+fde.ipLen {
		return FDE{}, errors.New("FDE not found")
	}

	return FDE{
		Start: fde.ipStart,
		End:   fde.ipStart + fde.ipLen,
	}, nil
}

type lookupHook struct {
	fde fdeInfo
}

func (f *lookupHook) fdeHook(_ *cieInfo, fde *fdeInfo) bool {
	f.fde = *fde
	return false
}
func (f *lookupHook) deltaHook(_ uintptr, _ *vmRegs, _ sdtypes.StackDelta) {}
func (f *lookupHook) golangHook(_, _ uintptr)                              {}
