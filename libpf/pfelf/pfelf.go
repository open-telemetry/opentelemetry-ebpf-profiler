// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// package pfelf implements functions for processing of ELF files and extracting data from
// them. This file provides convenience functions for golang debug/elf standard library.
package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

var ErrNoDebugLink = errors.New("no debug link")

// ParseDebugLink parses the name and CRC32 of the debug info file from the provided section data.
// Error is returned if the data is malformed.
func ParseDebugLink(data []byte) (linkName string, crc32 int32, err error) {
	strEnd := bytes.IndexByte(data, 0)
	if strEnd < 0 {
		return "", 0, errors.New("malformed debug link, not zero terminated")
	}
	linkName = strings.ToValidUTF8(string(data[:strEnd]), "")

	strEnd++
	// The link contains 0 to 3 bytes of padding after the null character, CRC32 is 32-bit aligned
	crc32StartIdx := strEnd + ((4 - (strEnd & 3)) & 3)
	if crc32StartIdx+4 > len(data) {
		return "", 0, fmt.Errorf("malformed debug link, no CRC32 (len %v, start index %v)",
			len(data), crc32StartIdx)
	}

	linkCRC32 := binary.LittleEndian.Uint32(data[crc32StartIdx : crc32StartIdx+4])

	return linkName, int32(linkCRC32), nil
}

var ErrNoBuildID = errors.New("no build ID")
var ubuntuKernelSignature = regexp.MustCompile(` \(Ubuntu[^)]*\)\n$`)

// getGoBuildIDFromNotes returns the Go build ID from an ELF notes section data.
func getGoBuildIDFromNotes(notes []byte) (string, error) {
	// Identify the Go Build ID with ELF_NOTE_GOBUILDID_TAG (0x4).
	buildID, found, err := getNoteString(notes, "Go", 0x4)
	if err != nil {
		return "", fmt.Errorf("could not determine BuildID: %v", err)
	}
	if !found {
		return "", ErrNoBuildID
	}
	return buildID, nil
}

// GetBuildIDFromNotesFile returns the build ID contained in a file with the format of an ELF notes
// section.
func GetBuildIDFromNotesFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("could not open %s: %w", filePath, err)
	}
	defer file.Close()
	data, err := io.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("could not read %s: %w", filePath, err)
	}
	return getBuildIDFromNotes(data)
}

// getBuildIDFromNotes returns the build ID from an ELF notes section data.
func getBuildIDFromNotes(notes []byte) (string, error) {
	// 0x3 is the "Build ID" type. Not sure where this is standardized.
	buildID, found, err := getNoteHexString(notes, "GNU", 0x3)
	if err != nil {
		return "", fmt.Errorf("could not determine BuildID: %v", err)
	}
	if !found {
		return "", ErrNoBuildID
	}
	return buildID, nil
}

// getNoteDescBytes returns the bytes contents of an ELF note from a note section, as described
// in the ELF standard in Figure 2-3.
func getNoteDescBytes(sectionBytes []byte, name string, noteType uint32) (
	noteBytes []byte, found bool, err error) {
	// The data stored inside ELF notes is made of one or multiple structs, containing the
	// following fields:
	// 	- namesz	// 32-bit, size of "name"
	// 	- descsz	// 32-bit, size of "desc"
	// 	- type		// 32-bit - 0x3 in case of a BuildID, 0x100 in case of build salt
	// 	- name		// namesz bytes, null terminated
	// 	- desc		// descsz bytes, binary data: the actual contents of the note
	// Because of this structure, the information of the build id starts at the 17th byte.

	// Null terminated string
	nameBytes := append([]byte(name), 0x0)
	noteTypeBytes := make([]byte, 4)

	binary.LittleEndian.PutUint32(noteTypeBytes, noteType)
	noteHeader := append(noteTypeBytes, nameBytes...) //nolint:gocritic

	// Try to find the note in the section
	idx := bytes.Index(sectionBytes, noteHeader)
	if idx == -1 {
		return nil, false, nil
	}
	if idx < 4 { // there needs to be room for descsz
		return nil, false, errors.New("could not read note data size")
	}

	idxDataStart := idx + len(noteHeader)
	idxDataStart += (4 - (idxDataStart & 3)) & 3 // data is 32bit-aligned, round up

	// read descsz and compute the last index of the note data
	dataSize := binary.LittleEndian.Uint32(sectionBytes[idx-4 : idx])
	idxDataEnd := uint64(idxDataStart) + uint64(dataSize)

	// Check sanity (84 is totally arbitrary, as we only use it for Linux ID and (Go) Build ID)
	if idxDataEnd > uint64(len(sectionBytes)) || dataSize > 84 {
		return nil, false, fmt.Errorf(
			"non-sensical note: %d start index: %d, %v end index %d, size %d, section size %d",
			idx, idxDataStart, noteHeader, idxDataEnd, dataSize, len(sectionBytes))
	}
	return sectionBytes[idxDataStart:idxDataEnd], true, nil
}

// getNoteHexString returns the hex string contents of an ELF note from a note section, as described
// in the ELF standard in Figure 2-3.
func getNoteHexString(sectionBytes []byte, name string, noteType uint32) (
	noteHexString string, found bool, err error) {
	noteBytes, found, err := getNoteDescBytes(sectionBytes, name, noteType)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, nil
	}
	return hex.EncodeToString(noteBytes), true, nil
}

func getNoteString(sectionBytes []byte, name string, noteType uint32) (
	noteString string, found bool, err error) {
	noteBytes, found, err := getNoteDescBytes(sectionBytes, name, noteType)
	if err != nil {
		return "", false, err
	}
	if !found {
		return "", false, nil
	}
	return string(noteBytes), true, nil
}
