// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBuildIDFromNotesFile(t *testing.T) {
	r := bytes.NewReader([]byte("\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00_notorious_build_id_"))
	buildID, err := getBuildIDFromNotesFile(r)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString([]byte("_notorious_build_id_")), buildID)
}

func TestGetBuildIDVisitsAllProgramNoteSegments(t *testing.T) {
	expected := "5883092a3cf39b3f4a8b5289b409829651c3ada3"
	desc, err := hex.DecodeString(expected)
	require.NoError(t, err)

	first := testELFNote("LINUX", 0, []byte("not a build ID"))
	second := testELFNote("GNU", 3, desc)
	data := append(append([]byte{}, first...), second...)

	f := &File{
		elfReader: bytes.NewReader(data),
		Progs: []Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Off: 0, Filesz: uint64(len(first))}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Off: uint64(len(first)), Filesz: uint64(len(second))}},
		},
		notesError: errNotProcessed,
	}

	buildID, err := f.GetBuildID()
	require.NoError(t, err)
	assert.Equal(t, expected, buildID)
}

func testELFNote(name string, noteType uint32, desc []byte) []byte {
	nameBytes := append([]byte(name), 0)
	note := make([]byte, 12)
	binary.LittleEndian.PutUint32(note[0:], uint32(len(nameBytes)))
	binary.LittleEndian.PutUint32(note[4:], uint32(len(desc)))
	binary.LittleEndian.PutUint32(note[8:], noteType)
	note = append(note, nameBytes...)
	note = append(note, make([]byte, alignNoteSize(len(note))-len(note))...)
	note = append(note, desc...)
	note = append(note, make([]byte, alignNoteSize(len(note))-len(note))...)
	return note
}
