// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package usdt

import (
	"debug/elf"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestParseSDTNotes(t *testing.T) {
	data := append(
		buildSDTNote(sdtNoteOwner, sdtNoteType, 0x1200, 0x1000, 0x2100,
			"otel_memory", "alloc", "8@%rdi"),
		buildSDTNote(sdtNoteOwner, sdtNoteType, 0x1300, 0x1000, 0,
			"otel_memory", "free", "8@%rdi")...,
	)

	notes, err := parseSDTNotes(data)
	require.NoError(t, err)
	require.Len(t, notes, 2)
	assert.Equal(t, sdtNote{
		provider:  "otel_memory",
		name:      "alloc",
		location:  0x1200,
		base:      0x1000,
		semaphore: 0x2100,
	}, notes[0])
	assert.Equal(t, "free", notes[1].name)
	assert.Zero(t, notes[1].semaphore)
}

func TestParseSDTNotesSkipsOtherNotes(t *testing.T) {
	data := append(
		buildSDTNote("other", sdtNoteType, 1, 2, 3, "provider", "probe", ""),
		buildSDTNote(sdtNoteOwner, 1, 1, 2, 3, "provider", "probe", "")...,
	)

	notes, err := parseSDTNotes(data)
	require.NoError(t, err)
	assert.Empty(t, notes)
}

func TestParseSDTNotesRejectsMalformedData(t *testing.T) {
	valid := buildSDTNote(sdtNoteOwner, sdtNoteType, 1, 2, 3, "provider", "probe", "")
	shortDesc := buildRawSDTNote(sdtNoteOwner, sdtNoteType, make([]byte, 23))
	missingProviderTerminator := buildRawSDTNote(sdtNoteOwner, sdtNoteType,
		append(make([]byte, 24), []byte("provider")...))
	missingNameTerminator := buildRawSDTNote(sdtNoteOwner, sdtNoteType,
		append(make([]byte, 24), []byte("provider\x00probe")...))

	tests := []struct {
		name string
		data []byte
	}{
		{name: "header", data: valid[:11]},
		{name: "owner", data: valid[:13]},
		{name: "descriptor", data: valid[:len(valid)-1]},
		{name: "short descriptor", data: shortDesc},
		{name: "provider terminator", data: missingProviderTerminator},
		{name: "name terminator", data: missingNameTerminator},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSDTNotes(tc.data)
			assert.Error(t, err)
		})
	}
}

func FuzzParseSDTNotes(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(buildSDTNote(sdtNoteOwner, sdtNoteType, 1, 2, 3, "provider", "probe", ""))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseSDTNotes(data)
	})
}

func TestAdjustedSDTAddress(t *testing.T) {
	tests := []struct {
		name                         string
		sectionBase, noteBase, input uint64
		want                         uint64
		wantErr                      bool
	}{
		{name: "no adjustment", input: 10, want: 10},
		{name: "add", sectionBase: 20, noteBase: 10, input: 100, want: 110},
		{name: "subtract", sectionBase: 10, noteBase: 20, input: 100, want: 90},
		{name: "overflow", sectionBase: 2, noteBase: 1, input: math.MaxUint64, wantErr: true},
		{name: "underflow", sectionBase: 1, noteBase: 3, input: 1, wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := adjustedSDTAddress(tc.sectionBase, tc.noteBase, tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestELFFileOffset(t *testing.T) {
	f := &pfelf.File{Progs: []pfelf.Prog{
		{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X,
			Vaddr: 0x1000, Off: 0x200, Filesz: 0x100, Memsz: 0x100,
		}},
		{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W,
			Vaddr: 0x2000, Off: 0x400, Filesz: 0x100, Memsz: 0x200,
		}},
	}}

	offset, err := elfFileOffset(f, 0x1020, true)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x220), offset)

	offset, err = elfFileOffset(f, 0x2020, false)
	require.NoError(t, err)
	assert.Equal(t, uint64(0x420), offset)

	_, err = elfFileOffset(f, 0x2020, true)
	assert.Error(t, err)
	_, err = elfFileOffset(f, 0x2150, false)
	assert.Error(t, err, "memory-only segment data has no file offset")
	_, err = elfFileOffset(f, 0x3000, false)
	assert.Error(t, err)
}

func buildSDTNote(owner string, noteType uint32, location, base, semaphore uint64,
	provider, name, arguments string,
) []byte {
	desc := make([]byte, 24)
	binary.LittleEndian.PutUint64(desc[0:8], location)
	binary.LittleEndian.PutUint64(desc[8:16], base)
	binary.LittleEndian.PutUint64(desc[16:24], semaphore)
	desc = append(desc, provider...)
	desc = append(desc, 0)
	desc = append(desc, name...)
	desc = append(desc, 0)
	desc = append(desc, arguments...)
	desc = append(desc, 0)
	return buildRawSDTNote(owner, noteType, desc)
}

func buildRawSDTNote(owner string, noteType uint32, desc []byte) []byte {
	name := append([]byte(owner), 0)
	note := make([]byte, 12)
	binary.LittleEndian.PutUint32(note[0:4], uint32(len(name)))
	binary.LittleEndian.PutUint32(note[4:8], uint32(len(desc)))
	binary.LittleEndian.PutUint32(note[8:12], noteType)
	note = append(note, name...)
	note = append(note, make([]byte, int(align4(uint64(len(name))))-len(name))...)
	note = append(note, desc...)
	note = append(note, make([]byte, int(align4(uint64(len(desc))))-len(desc))...)
	return note
}
