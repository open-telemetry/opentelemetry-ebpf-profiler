// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"errors"
	"sort"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

type FDE struct {
	PCBegin uintptr
	PCRange uintptr
}

// LookupFDE performs a binary search in .eh_frame_hdr for an FDE covering the given addr.
func LookupFDE(ef *pfelf.File, addr libpf.Address) (FDE, error) {
	t, err := newEhFrameTable(ef)
	if err != nil {
		return FDE{}, err
	}

	idx := sort.Search(t.count(), func(idx int) bool {
		t.position(idx)
		ipStart, _, _ := t.parseHdrEntry() // ignoring error, check bounds later
		return ipStart > uintptr(addr)
	})
	idx--
	if idx < 0 {
		return FDE{}, errors.New("FDE not found")
	}
	t.position(idx)
	ipStart, fr, entryErr := t.parseHdrEntry()
	if entryErr != nil {
		return FDE{}, entryErr
	}
	_, fde, _, err := parseFDEHDR(&fr, ef, ipStart, t.cieCache)
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
