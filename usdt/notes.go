// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt // import "go.opentelemetry.io/ebpf-profiler/usdt"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

const (
	sdtNoteSection = ".note.stapsdt"
	sdtBaseSection = ".stapsdt.base"
)

// sdtNote is the raw, address-based representation stored in an SDT note.
// Discovery later converts its addresses to ELF file offsets.
type sdtNote struct {
	provider  string
	name      string
	location  uint64
	base      uint64
	semaphore uint64
}

// readSDTNotes reads every SystemTap note and returns the address of
// `.stapsdt.base`, which is needed to undo prelink address adjustments.
func readSDTNotes(f *pfelf.File) ([]sdtNote, uint64, error) {
	var notes []sdtNote
	var parseErr error
	err := f.VisitNoteSections([]string{sdtNoteSection}, func(id uint64, desc []byte) bool {
		// A note section may contain records owned by other producers.
		if id != pfelf.NoteStapSDT {
			return true
		}
		note, err := parseSDTDescriptor(desc)
		if err != nil {
			parseErr = err
			return false
		}
		notes = append(notes, note)
		return true
	})
	if parseErr != nil {
		return nil, 0, parseErr
	}
	if err != nil && !errors.Is(err, pfelf.ErrNoteNotFound) {
		return nil, 0, fmt.Errorf("read section %s: %w", sdtNoteSection, err)
	}
	if len(notes) == 0 {
		return nil, 0, nil
	}

	base := f.Section(sdtBaseSection)
	if base == nil || base.Addr == 0 {
		return nil, 0, fmt.Errorf("SDT notes found without a valid %s section", sdtBaseSection)
	}
	return notes, base.Addr, nil
}

// parseSDTDescriptor decodes the descriptor of one SDT note. Format references:
//   - https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
//   - https://docs.ebpf.io/linux/concepts/usdt/
//
// The descriptor starts with three little-endian 64-bit addresses followed by
// provider, name, and arguments as NUL-terminated strings. This matches the
// ELF64, little-endian files accepted by pfelf.
func parseSDTDescriptor(desc []byte) (sdtNote, error) {
	if len(desc) < 24 {
		return sdtNote{}, errors.New("SDT note descriptor is too short")
	}
	provider, rest, ok := bytes.Cut(desc[24:], []byte{0})
	if !ok {
		return sdtNote{}, errors.New("SDT note provider is not terminated")
	}
	name, _, ok := bytes.Cut(rest, []byte{0})
	if !ok {
		return sdtNote{}, errors.New("SDT note name is not terminated")
	}
	return sdtNote{
		provider:  string(provider),
		name:      string(name),
		location:  binary.LittleEndian.Uint64(desc[0:8]),
		base:      binary.LittleEndian.Uint64(desc[8:16]),
		semaphore: binary.LittleEndian.Uint64(desc[16:24]),
	}, nil
}

// adjustedSDTAddress applies the difference between the note's link-time
// `.stapsdt.base` address and the section's current address. Legacy prelink may
// update the section address without updating the non-allocated note contents.
// If either base is unavailable, or if they match, no adjustment is needed.
func adjustedSDTAddress(sectionBase, noteBase, address uint64) (uint64, error) {
	if sectionBase == 0 || noteBase == 0 {
		return address, nil
	}
	if sectionBase >= noteBase {
		delta := sectionBase - noteBase
		if address > math.MaxUint64-delta {
			return 0, errors.New("SDT address adjustment overflows")
		}
		return address + delta, nil
	}

	delta := noteBase - sectionBase
	if address < delta {
		return 0, errors.New("SDT address adjustment underflows")
	}
	return address - delta, nil
}

// elfFileOffset translates a virtual address from an SDT descriptor into the
// file offset expected by uprobe attachment. Probe locations must be in an
// executable PT_LOAD; semaphore locations may be in any file-backed PT_LOAD.
func elfFileOffset(f *pfelf.File, address uint64, executable bool) (uint64, error) {
	for i := range f.Progs {
		prog := &f.Progs[i]
		if prog.Type != elf.PT_LOAD || executable && prog.Flags&elf.PF_X == 0 {
			continue
		}
		if address < prog.Vaddr {
			continue
		}
		delta := address - prog.Vaddr
		if delta >= prog.Filesz {
			continue
		}
		if prog.Off > math.MaxUint64-delta {
			return 0, errors.New("SDT file offset overflows")
		}
		return prog.Off + delta, nil
	}
	return 0, fmt.Errorf("SDT address %#x is not in a suitable load segment", address)
}
