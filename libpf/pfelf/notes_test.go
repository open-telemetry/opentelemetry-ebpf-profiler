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

func TestGetBuildIDFromNotesFileReturnsErrNoBuildID(t *testing.T) {
	r := bytes.NewReader(testELFNote("LINUX", 0, []byte("not a build ID")))
	buildID, err := getBuildIDFromNotesFile(r)
	require.ErrorIs(t, err, ErrNoBuildID)
	assert.Empty(t, buildID)
}

func TestVisitNotesReturnsErrNoteNotFound(t *testing.T) {
	data := testELFNote("LINUX", 0, []byte("not a build ID"))
	f := &File{
		elfReader: bytes.NewReader(data),
		Progs: []Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Filesz: uint64(len(data))}},
		},
	}

	visited := 0
	err := f.VisitNotes(func(_ uint64, _ []byte) bool {
		visited++
		return true
	})
	require.ErrorIs(t, err, ErrNoteNotFound)
	assert.Equal(t, 1, visited)
}

func TestVisitNotesReturnsNilWhenVisitorStops(t *testing.T) {
	first := testELFNote("LINUX", 0, []byte("not a build ID"))
	second := testELFNote("GNU", 3, []byte("_notorious_build_id_"))
	data := append(append([]byte{}, first...), second...)
	f := &File{
		elfReader: bytes.NewReader(data),
		Progs: []Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Off: 0, Filesz: uint64(len(first))}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Off: uint64(len(first)), Filesz: uint64(len(second))}},
		},
	}

	var visited []uint64
	err := f.VisitNotes(func(note uint64, _ []byte) bool {
		visited = append(visited, note)
		return note != NoteGnuBuildId
	})
	require.NoError(t, err)
	assert.Equal(t, []uint64{NamespaceLinux, NoteGnuBuildId}, visited)
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

func TestGetBuildIDReadsNamedNoteSection(t *testing.T) {
	expected := "e4b38c63b6127d09ccaf62932cfb72bbf2240fbe"
	desc, err := hex.DecodeString(expected)
	require.NoError(t, err)

	goNote := testELFNote("Go", 4, []byte("go-build-id"))
	gnuNote := testELFNote("GNU", 3, desc)
	shstrtab := []byte("\x00.note.gnu.build-id\x00.shstrtab\x00")
	sectionHeaderOffset := len(goNote) + len(gnuNote) + len(shstrtab)

	var sectionHeaders bytes.Buffer
	require.NoError(t, binary.Write(&sectionHeaders, binary.LittleEndian, []elf.Section64{
		{},
		{
			Name:      1,
			Type:      uint32(elf.SHT_NOTE),
			Off:       uint64(len(goNote)),
			Size:      uint64(len(gnuNote)),
			Addralign: 4,
		},
		{
			Name:      uint32(len("\x00.note.gnu.build-id\x00")),
			Type:      uint32(elf.SHT_STRTAB),
			Off:       uint64(len(goNote) + len(gnuNote)),
			Size:      uint64(len(shstrtab)),
			Addralign: 1,
		},
	}))

	data := make([]byte, 0, sectionHeaderOffset+sectionHeaders.Len())
	data = append(data, goNote...)
	data = append(data, gnuNote...)
	data = append(data, shstrtab...)
	data = append(data, sectionHeaders.Bytes()...)

	f := &File{
		elfReader: bytes.NewReader(data),
		Progs: []Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Off: 0, Filesz: uint64(len(goNote))}},
			{ProgHeader: elf.ProgHeader{Type: elf.PT_LOAD, Off: 0, Filesz: uint64(len(goNote) + len(gnuNote))}},
		},
		elfHeader: elf.Header64{
			Shoff:    uint64(sectionHeaderOffset),
			Shnum:    3,
			Shstrndx: 2,
		},
		notesError: errNotProcessed,
	}

	buildID, err := f.GetBuildID()
	require.NoError(t, err)
	assert.Equal(t, expected, buildID)
}

func TestGetBuildIDInsideCoreUsesProgramNotes(t *testing.T) {
	expected := "5883092a3cf39b3f4a8b5289b409829651c3ada3"
	programDesc, err := hex.DecodeString(expected)
	require.NoError(t, err)

	sectionDesc, err := hex.DecodeString("e4b38c63b6127d09ccaf62932cfb72bbf2240fbe")
	require.NoError(t, err)

	programNote := testELFNote("GNU", 3, programDesc)
	sectionNote := testELFNote("GNU", 3, sectionDesc)
	shstrtab := []byte("\x00.note.gnu.build-id\x00.shstrtab\x00")
	sectionHeaderOffset := len(programNote) + len(sectionNote) + len(shstrtab)

	var sectionHeaders bytes.Buffer
	require.NoError(t, binary.Write(&sectionHeaders, binary.LittleEndian, []elf.Section64{
		{},
		{
			Name:      1,
			Type:      uint32(elf.SHT_NOTE),
			Off:       uint64(len(programNote)),
			Size:      uint64(len(sectionNote)),
			Addralign: 4,
		},
		{
			Name:      uint32(len("\x00.note.gnu.build-id\x00")),
			Type:      uint32(elf.SHT_STRTAB),
			Off:       uint64(len(programNote) + len(sectionNote)),
			Size:      uint64(len(shstrtab)),
			Addralign: 1,
		},
	}))

	data := make([]byte, 0, sectionHeaderOffset+sectionHeaders.Len())
	data = append(data, programNote...)
	data = append(data, sectionNote...)
	data = append(data, shstrtab...)
	data = append(data, sectionHeaders.Bytes()...)

	f := &File{
		elfReader:  bytes.NewReader(data),
		InsideCore: true,
		Progs: []Prog{
			{ProgHeader: elf.ProgHeader{Type: elf.PT_NOTE, Off: 0, Filesz: uint64(len(programNote))}},
		},
		elfHeader: elf.Header64{
			Shoff:    uint64(sectionHeaderOffset),
			Shnum:    3,
			Shstrndx: 2,
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
