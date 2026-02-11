// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"encoding/binary"
	"strings"
)

// USDTProbe represents a USDT probe found in ELF with file-offset-adjusted addresses
type USDTProbe struct {
	Provider        string
	Name            string
	Location        uint64 // File offset for uprobe attachment
	Base            uint64 // Original base address from note
	SemaphoreOffset uint64 // File offset for semaphore
	Arguments       string
}

// ParseUSDTProbes reads USDT probe information from ELF .note.stapsdt section.
// It applies prelink adjustments if .stapsdt.base section exists, and converts
// virtual addresses to file offsets suitable for uprobe attachment.
func (f *File) ParseUSDTProbes() ([]USDTProbe, error) {
	var probes []USDTProbe

	// Find .note.stapsdt section
	var stapsdt *Section
	for i := range f.Sections {
		if f.Sections[i].Name == ".note.stapsdt" {
			stapsdt = &f.Sections[i]
			break
		}
	}
	if stapsdt == nil {
		return nil, nil // No USDT probes in this binary
	}

	data, err := stapsdt.Data(16 * 1024)
	if err != nil {
		return nil, err
	}

	// Find .stapsdt.base section address for prelink adjustment
	var baseAddr uint64
	for i := range f.Sections {
		if f.Sections[i].Name == ".stapsdt.base" {
			baseAddr = f.Sections[i].Addr
			break
		}
	}

	// Parse note entries
	offset := 0
	for offset < len(data) {
		if offset+12 > len(data) {
			break
		}

		// Note header: namesz(4) + descsz(4) + type(4)
		namesz := binary.LittleEndian.Uint32(data[offset : offset+4])
		descsz := binary.LittleEndian.Uint32(data[offset+4 : offset+8])
		noteType := binary.LittleEndian.Uint32(data[offset+8 : offset+12])
		offset += 12

		if noteType != 3 { // NT_STAPSDT
			// Skip this note
			nameEnd := offset + int((namesz+3)&^3) // align to 4 bytes
			descEnd := nameEnd + int((descsz+3)&^3)
			offset = descEnd
			continue
		}

		// Skip owner name (should be "stapsdt")
		nameEnd := offset + int((namesz+3)&^3)

		if nameEnd+int(descsz) > len(data) {
			break
		}

		// Parse descriptor
		desc := data[nameEnd : nameEnd+int(descsz)]
		if len(desc) < 24 { // 3 uint64 values
			offset = nameEnd + int((descsz+3)&^3)
			continue
		}

		location := binary.LittleEndian.Uint64(desc[0:8])
		noteBase := binary.LittleEndian.Uint64(desc[8:16])
		semaphore := binary.LittleEndian.Uint64(desc[16:24])

		// Apply prelink adjustment if .stapsdt.base section exists
		// See: https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
		if baseAddr != 0 && noteBase != 0 {
			diff := baseAddr - noteBase
			location += diff
			if semaphore != 0 {
				semaphore += diff
			}
		}

		// Convert virtual address to file offset for uprobe attachment
		prog := f.findVirtualAddressProg(location)
		if prog != nil {
			location = location - prog.Vaddr + prog.Off
		}

		// Convert semaphore virtual address to file offset
		var semaphoreFileOffset uint64
		if semaphore != 0 {
			semaProg := f.findVirtualAddressProg(semaphore)
			if semaProg != nil {
				semaphoreFileOffset = semaphore - semaProg.Vaddr + semaProg.Off
			}
		}

		// Parse strings: provider\0probe\0arguments\0
		stringData := desc[24:]
		strings := strings.Split(string(stringData), "\x00")
		if len(strings) >= 3 {
			probe := USDTProbe{
				Provider:        strings[0],
				Name:            strings[1],
				Location:        location,
				Base:            noteBase,
				SemaphoreOffset: semaphoreFileOffset,
				Arguments:       strings[2],
			}
			probes = append(probes, probe)
		}

		offset = nameEnd + int((descsz+3)&^3)
	}

	return probes, nil
}
