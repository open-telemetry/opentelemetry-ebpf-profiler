// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// package pfelf implements functions for processing of ELF files and extracting data from
// them. This file provides enumeration of ELF Notes and debug link handling
package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
)

// ELF64 Note header.
type note64 struct {
	Namesz, Descsz, Type uint32
}

const (
	NamespaceUnknown uint64 = iota << 32
	NamespaceCore
	NamespaceLinux
	NamespaceGNU
	NamespaceGo

	NoteGnuBuildId = NamespaceGNU + 0x3

	NoteGoBuildId = NamespaceGo + 0x4
)

// visitNotes parses and visits all notes from pfbufio.Reader.
// The visitor must make copies of the 'data' it keeps after return.
// The returned bool is true if the visitor stopped iteration.
func visitNotes(rdr *pfbufio.Reader, visitor func(uint64, []byte) bool) (bool, error) {
	var note note64
	var buf []byte
	for {
		// Read the note header (name and size lengths), followed by reading
		// their contents. This code advances the position in 'rdr' and should
		// be kept together to parse the notes correctly.
		if n, err := rdr.Read(pfunsafe.FromPointer(&note)); err != nil {
			if n == 0 && err == io.EOF {
				err = nil
			}
			return false, err
		}

		id := NamespaceUnknown
		alignedSize := alignNoteSize(int(note.Namesz))
		namespace, err := rdr.ReadN(alignedSize)
		switch err {
		case nil:
			switch strings.TrimRight(pfunsafe.ToString(namespace[:note.Namesz]), "\x00") {
			case "CORE":
				id = NamespaceCore
			case "LINUX":
				id = NamespaceLinux
			case "GNU":
				id = NamespaceGNU
			case "Go":
				id = NamespaceGo
			}
		case pfbufio.ErrBufferTooSmall:
			if _, err = rdr.Discard(alignedSize); err != nil {
				return false, err
			}
		default:
			return false, err
		}

		alignedSize = alignNoteSize(int(note.Descsz))
		desc, err := rdr.ReadN(alignedSize)
		switch err {
		case nil:
			// Nothing
		case pfbufio.ErrBufferTooSmall:
			if cap(buf) < alignedSize {
				buf = make([]byte, alignedSize)
			}
			buf = buf[:alignedSize]
			if _, err = rdr.Read(buf); err != nil {
				return false, err
			}
			desc = buf
		default:
			return false, err
		}
		if !visitor(id+uint64(note.Type), desc[:note.Descsz]) {
			return true, nil
		}
	}
}

// alignNoteSize rounds size up to the nearest multiple of 4.
func alignNoteSize(size int) int {
	return (size + 3) &^ 3
}

func getBuildIDFromNotesFile(r io.ReaderAt) (string, error) {
	rdr := pfbufio.NewReader(r, 0, 1<<63-1)
	defer pfbufio.PutReader(rdr)

	var buildId string
	_, err := visitNotes(rdr, func(note uint64, desc []byte) bool {
		if note == NoteGnuBuildId {
			buildId = hex.EncodeToString(desc)
			return false
		}
		return true
	})
	return buildId, err
}

// GetBuildIDFromNotesFile returns the build ID contained in a file with
// the format of an ELF notes.
func GetBuildIDFromNotesFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("could not open %s: %w", filePath, err)
	}
	defer file.Close()

	return getBuildIDFromNotesFile(file)

}

// ParseDebugLink parses the name and CRC32 of the debug info file from the provided section data.
// Error is returned if the data is malformed.
func ParseDebugLink(data []byte) (linkName string, crc32 int32, err error) {
	strEnd := bytes.IndexByte(data, 0)
	if strEnd <= 0 {
		return "", 0, fmt.Errorf("malformed debug link, not zero terminated (len %v)", len(data))
	}
	linkName = string(data[:strEnd])
	if !utf8.ValidString(linkName) {
		return "", 0, fmt.Errorf("malformed debug link, invalid bytes (len %v)", len(data))
	}
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
