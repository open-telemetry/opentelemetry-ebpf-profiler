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
	sdtNoteType  = 3
	sdtNoteOwner = "stapsdt"

	// Bound allocations when parsing an untrusted ELF file.
	maxSDTSectionSize = 16 << 20
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

// readSDTNotes reads every SystemTap note section and returns the address of
// `.stapsdt.base`, which is needed to undo prelink address adjustments.
func readSDTNotes(f *pfelf.File) ([]sdtNote, uint64, error) {
	if err := f.LoadSections(); err != nil {
		return nil, 0, err
	}

	var baseAddr uint64
	for i := range f.Sections {
		if f.Sections[i].Name == ".stapsdt.base" {
			baseAddr = f.Sections[i].Addr
			break
		}
	}

	var notes []sdtNote
	for i := range f.Sections {
		section := &f.Sections[i]
		if section.Name != ".note.stapsdt" {
			continue
		}
		if section.Type != elf.SHT_NOTE {
			return nil, 0, fmt.Errorf("section %s has type %s", section.Name, section.Type)
		}
		if section.FileSize > maxSDTSectionSize {
			return nil, 0, fmt.Errorf("section %s is too large: %d", section.Name, section.FileSize)
		}
		data, err := section.Data(maxSDTSectionSize)
		if err != nil {
			return nil, 0, fmt.Errorf("read section %s: %w", section.Name, err)
		}
		parsed, err := parseSDTNotes(data)
		if err != nil {
			return nil, 0, err
		}
		notes = append(notes, parsed...)
	}
	if len(notes) > 0 && baseAddr == 0 {
		return nil, 0, errors.New("SDT notes found without a valid .stapsdt.base section")
	}
	return notes, baseAddr, nil
}

// parseSDTNotes decodes the ELF note stream. Format references:
//   - https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
//   - https://docs.ebpf.io/linux/concepts/usdt/
//
// Each record contains a 12-byte header followed by a four-byte-aligned owner
// and descriptor. An SDT descriptor starts with three little-endian 64-bit
// addresses followed by provider, name, and arguments as NUL-terminated
// strings. This matches the ELF64,
// little-endian files accepted by pfelf. We do not need the arguments yet.
func parseSDTNotes(data []byte) ([]sdtNote, error) {
	const headerSize = 12
	var notes []sdtNote

	for offset := 0; offset < len(data); {
		if len(data)-offset < headerSize {
			return nil, errors.New("truncated SDT note header")
		}

		namesz := binary.LittleEndian.Uint32(data[offset:])
		descsz := binary.LittleEndian.Uint32(data[offset+4:])
		noteType := binary.LittleEndian.Uint32(data[offset+8:])
		offset += headerSize

		nameLen := align4(uint64(namesz))
		descLen := align4(uint64(descsz))
		if nameLen > uint64(len(data)-offset) {
			return nil, errors.New("truncated SDT note owner")
		}
		name := data[offset : offset+int(namesz)]
		offset += int(nameLen)
		if descLen > uint64(len(data)-offset) {
			return nil, errors.New("truncated SDT note descriptor")
		}
		desc := data[offset : offset+int(descsz)]
		offset += int(descLen)

		// A note section may contain records owned by other producers.
		if noteType != sdtNoteType || string(bytes.TrimRight(name, "\x00")) != sdtNoteOwner {
			continue
		}
		if len(desc) < 24 {
			return nil, errors.New("SDT note descriptor is too short")
		}

		provider, rest, ok := cutCString(desc[24:])
		if !ok {
			return nil, errors.New("SDT note provider is not terminated")
		}
		name, _, ok = cutCString(rest)
		if !ok {
			return nil, errors.New("SDT note name is not terminated")
		}

		notes = append(notes, sdtNote{
			provider:  string(provider),
			name:      string(name),
			location:  binary.LittleEndian.Uint64(desc[0:8]),
			base:      binary.LittleEndian.Uint64(desc[8:16]),
			semaphore: binary.LittleEndian.Uint64(desc[16:24]),
		})
	}
	return notes, nil
}

func cutCString(data []byte) ([]byte, []byte, bool) {
	value, rest, ok := bytes.Cut(data, []byte{0})
	return value, rest, ok
}

func align4(value uint64) uint64 {
	return (value + 3) &^ 3
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
