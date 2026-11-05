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

func TestParseSDTDescriptor(t *testing.T) {
	note, err := parseSDTDescriptor(buildSDTDescriptor(
		0x1200, 0x1000, 0x2100, "otel_memory", "alloc", "8@%rdi"))
	require.NoError(t, err)
	assert.Equal(t, sdtNote{
		provider:  "otel_memory",
		name:      "alloc",
		location:  0x1200,
		base:      0x1000,
		semaphore: 0x2100,
	}, note)
}

func TestParseSDTDescriptorNoSemaphore(t *testing.T) {
	note, err := parseSDTDescriptor(buildSDTDescriptor(
		0x1300, 0x1000, 0, "otel_memory", "free", "8@%rdi"))
	require.NoError(t, err)
	assert.Equal(t, "free", note.name)
	assert.Zero(t, note.semaphore)
}

func TestParseSDTDescriptorRejectsMalformed(t *testing.T) {
	valid := buildSDTDescriptor(1, 2, 3, "provider", "probe", "")

	tests := []struct {
		name string
		desc []byte
	}{
		{name: "short descriptor", desc: make([]byte, 23)},
		{name: "missing provider terminator",
			desc: append(make([]byte, 24), []byte("provider")...)},
		{name: "missing name terminator",
			desc: append(make([]byte, 24), []byte("provider\x00probe")...)},
		{name: "truncated addresses", desc: valid[:20]},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSDTDescriptor(tc.desc)
			assert.Error(t, err)
		})
	}
}

func FuzzParseSDTDescriptor(f *testing.F) {
	f.Add([]byte(nil))
	f.Add(buildSDTDescriptor(1, 2, 3, "provider", "probe", ""))
	f.Fuzz(func(_ *testing.T, data []byte) {
		_, _ = parseSDTDescriptor(data)
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
	require.Error(t, err)
	_, err = elfFileOffset(f, 0x2150, false)
	require.Error(t, err, "memory-only segment data has no file offset")
	_, err = elfFileOffset(f, 0x3000, false)
	require.Error(t, err)
}

func TestAttachmentPointsFromNotesContinuesAfterError(t *testing.T) {
	f := &pfelf.File{Progs: []pfelf.Prog{
		{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X,
			Vaddr: 0x1000, Off: 0x200, Filesz: 0x100,
		}},
		{ProgHeader: elf.ProgHeader{
			Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W,
			Vaddr: 0x2000, Off: 0x400, Filesz: 0x100,
		}},
	}}
	notes := []sdtNote{
		{provider: "provider", name: "bad", location: 0x3000, base: 0x1000},
		{provider: "provider", name: "alloc", location: 0x1020, base: 0x1000,
			semaphore: 0x2020},
	}

	points, err := attachmentPointsFromNotes(f, 0x1000, notes)
	require.ErrorContains(t, err, "provider:bad")
	require.Equal(t, []AttachmentPoint{{
		Provider:        "provider",
		Name:            "alloc",
		Location:        0x220,
		SemaphoreOffset: 0x420,
	}}, points)
}

// buildSDTDescriptor builds the binary descriptor payload for a single SDT note.
func buildSDTDescriptor(location, base, semaphore uint64,
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
	return desc
}
