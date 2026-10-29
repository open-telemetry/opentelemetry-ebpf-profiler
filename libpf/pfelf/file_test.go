// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"go/version"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/testsupport"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"
	"go.opentelemetry.io/ebpf-profiler/libpf/readatbuf"
)

func getPFELF(t *testing.T, path string) *File {
	t.Helper()
	testsupport.RequireGeneratedTestFile(t, path)
	file, err := Open(path)
	require.NoError(t, err)
	return file
}

func TestGnuHash(t *testing.T) {
	assert.Equal(t, uint32(0x00001505), calcGNUHash(""))
	assert.Equal(t, uint32(0x156b2bb8), calcGNUHash("printf"))
	assert.Equal(t, uint32(0x7c967e3f), calcGNUHash("exit"))
	assert.Equal(t, uint32(0xbac212a0), calcGNUHash("syscall"))
}

func lookupSymbolAddress(ef *File, name libpf.SymbolName) libpf.SymbolValue {
	val, _ := ef.LookupSymbolAddress(name)
	return val
}

func TestPFELFSymbols(t *testing.T) {
	exePath, err := testsupport.WriteSharedLibrary()
	require.NoError(t, err)
	defer os.Remove(exePath)

	ef, err := Open(exePath)
	require.NoError(t, err)
	defer ef.Close()

	stdELF, err := elf.Open(exePath)
	require.NoError(t, err)
	defer stdELF.Close()
	dynSyms, err := stdELF.DynamicSymbols()
	require.NoError(t, err)
	sections := make(map[libpf.SymbolName]uint16, len(dynSyms))
	for _, sym := range dynSyms {
		sections[libpf.SymbolName(sym.Name)] = uint16(sym.Section)
	}
	checkSection := func() {
		sym, err := ef.LookupSymbol("func")
		require.NoError(t, err)
		require.Contains(t, sections, sym.Name)
		assert.Equal(t, sections[sym.Name], sym.Shndx)
	}

	// Test GNU hash lookup
	checkSection()
	assert.Equal(t, libpf.SymbolValue(0x1000), lookupSymbolAddress(ef, "func"))
	assert.Equal(t, libpf.SymbolValueInvalid, lookupSymbolAddress(ef, "not_existent"))

	// Test SYSV lookup
	ef.gnuHash.addr = 0
	checkSection()
	assert.Equal(t, libpf.SymbolValue(0x1000), lookupSymbolAddress(ef, "func"))
	assert.Equal(t, libpf.SymbolValueInvalid, lookupSymbolAddress(ef, "not_existent"))

	visited := 0
	require.NoError(t, ef.VisitDynamicSymbols(func(sym libpf.Symbol) bool {
		if sym.Name != "" {
			require.Contains(t, sections, sym.Name)
			assert.Equal(t, sections[sym.Name], sym.Shndx)
			visited++
		}
		return true
	}))
	require.Positive(t, visited)
}

func TestReadSymbolData(t *testing.T) {
	exePath, err := testsupport.WriteSharedLibrary()
	require.NoError(t, err)
	defer os.Remove(exePath)

	ef, err := Open(exePath)
	require.NoError(t, err)
	defer ef.Close()

	sym, err := ef.LookupSymbol("func")
	require.NoError(t, err)

	data, err := ef.ReadSymbolData(sym, 4)
	require.NoError(t, err)
	assert.Len(t, data, int(min(sym.Size, 4)))

	// A crafted st_size that overflows int must not panic.
	huge := *sym
	huge.Size = 1 << 63
	data, err = ef.ReadSymbolData(&huge, 4)
	require.NoError(t, err)
	assert.Len(t, data, 4)
}

func TestPFELFSections(t *testing.T) {
	testsupport.RequireGeneratedTestFile(t, "testdata/fixed-address")
	elfFile, err := Open("testdata/fixed-address")
	require.NoError(t, err)
	defer elfFile.Close()

	// The fixed-address test executable has a section named `.coffee_section` at address 0xC0FFEE0
	sh := elfFile.Section(".coffee_section")
	if assert.NotNil(t, sh) {
		assert.Equal(t, ".coffee_section", sh.Name)
		assert.Equal(t, uint64(0xC0FFEE0), sh.Addr)

		// Try to find a section that does not exist
		sh = elfFile.Section(".tea_section")
		assert.Nil(t, sh)
	}
}

func testPFELFIsGolang(t *testing.T, filename string, isGoExpected bool) {
	t.Helper()
	ef := getPFELF(t, filename)
	defer ef.Close()
	assert.Equal(t, isGoExpected, ef.IsGolang())
}

func TestPFELFIsGolang(t *testing.T) {
	testPFELFIsGolang(t, "testdata/go-binary", true)
	testPFELFIsGolang(t, "testdata/without-debug-syms", false)
}

func TestGoVersion(t *testing.T) {
	ef := getPFELF(t, "testdata/go-binary")
	defer ef.Close()

	vers := ef.GoVersion()
	assert.GreaterOrEqual(t, version.Compare(vers, "go1.23.6"), 0)

	testEF := getPFELF(t, "/proc/self/exe")
	defer testEF.Close()
	testVersion := testEF.GoVersion()
	assert.Equal(t, runtime.Version(), testVersion)
}

func TestParseGoBuildinfoFallback(t *testing.T) {
	want, err := buildinfo.ReadFile("testdata/go-binary")
	require.NoError(t, err)

	// magicStripped loads go-binary-no-sections and zeroes out the
	// buildinfo magic in memory, simulating a coredump so incomplete that
	// even the PT_LOAD fallback scan can't locate it.
	magicStripped := func(t *testing.T) *File {
		t.Helper()
		testsupport.RequireGeneratedTestFile(t, "testdata/go-binary-no-sections")
		raw, err := os.ReadFile("testdata/go-binary-no-sections")
		require.NoError(t, err)

		i := bytes.Index(raw, goBuildInfoMagic)
		require.GreaterOrEqualf(t, i, 0, "test fixture no longer contains the buildinfo magic %q", goBuildInfoMagic)
		corrupted := append([]byte(nil), raw...)
		clear(corrupted[i : i+len(goBuildInfoMagic)])

		ef, err := NewFile(bytes.NewReader(corrupted), 0, false)
		require.NoError(t, err)
		return ef
	}
	open := func(path string) func(t *testing.T) *File {
		t.Helper()
		return func(t *testing.T) *File {
			t.Helper()
			return getPFELF(t, path)
		}
	}

	tests := map[string]struct {
		open              func(t *testing.T) *File
		wantSection       bool
		wantOtherSections bool
		wantIsGolang      bool
		wantVersion       string
	}{
		"buildinfo section present": {
			open:        open("testdata/go-binary"),
			wantSection: true, wantOtherSections: true,
			wantIsGolang: true, wantVersion: want.GoVersion,
		},
		"buildinfo section renamed away": {
			open:        open("testdata/go-binary-no-buildinfo-section"),
			wantSection: false, wantOtherSections: true,
			wantIsGolang: true, wantVersion: want.GoVersion,
		},
		"no section headers at all": {
			open:        open("testdata/go-binary-no-sections"),
			wantSection: false, wantOtherSections: false,
			wantIsGolang: true, wantVersion: want.GoVersion,
		},
		"not a Go binary": {
			open:        open("testdata/without-debug-syms"),
			wantSection: false, wantOtherSections: false,
			wantIsGolang: false, wantVersion: "",
		},
		"buildinfo magic missing from a section-less ELF": {
			open:        magicStripped,
			wantSection: false, wantOtherSections: false,
			wantIsGolang: true, wantVersion: "",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ef := tc.open(t)
			defer ef.Close()

			assert.Equal(t, tc.wantSection, ef.Section(".go.buildinfo") != nil)
			assert.Equal(t, tc.wantOtherSections, ef.Section(".gopclntab") != nil)
			assert.Equal(t, tc.wantIsGolang, ef.IsGolang())
			assert.Equal(t, tc.wantVersion, ef.GoVersion())
		})
	}
}

func TestGetGoBuildID(t *testing.T) {
	ef := getPFELF(t, "testdata/go-binary")
	defer ef.Close()

	buildID, err := ef.GetGoBuildID()
	require.NoError(t, err)
	testsupport.RequireGeneratedTestFile(t, "testdata/go-binary")
	out, err := exec.Command("go", "tool", "buildid", "testdata/go-binary").Output()
	require.NoError(t, err)
	expectedBuildID := strings.TrimRight(string(out), "\n")
	assert.Equal(t, expectedBuildID, buildID)
}

// TestFileTakeRefcount verifies that the underlying reader stays readable
// after Close while a Take reference is outstanding, and is closed when the
// last reference is dropped.
func TestFileTakeRefcount(t *testing.T) {
	ef := getPFELF(t, "testdata/go-binary")

	// Open() owns the source file, its page cache, and a memory mapping.
	require.IsType(t, &os.File{}, ef.resources.closer)
	assert.NotNil(t, ef.resources.cache)
	assert.NotNil(t, ef.resources.mmap)

	dataRef := ef.Take()
	// Close the File: the reference keeps the underlying reader open.
	require.NoError(t, ef.Close())

	// The File is closed, but the reference keeps the reader readable.
	progs := make([]byte, 64)
	_, err := ef.Underlying().ReadAt(progs, 0)
	require.NoError(t, err)

	// A second Take/Close pair is balanced; the reader is still open.
	dataRef2 := ef.Take()
	require.NoError(t, dataRef2.Close())
	_, err = ef.Underlying().ReadAt(progs, 0)
	require.NoError(t, err)

	// Dropping the last reference closes the reader and unmaps the mapping.
	require.NoError(t, dataRef.Close())
	assert.Nil(t, dataRef.(*fileResources).mmap)
	_, err = ef.Underlying().ReadAt(progs, 0)
	assert.Error(t, err)
}

// TestFileBorrowedReaderTake verifies that Take returns the no-op closer,
// and Close releases nothing, for Files that only borrow the reader from
// the caller.
func TestFileBorrowedReaderTake(t *testing.T) {
	testsupport.RequireGeneratedTestFile(t, "testdata/go-binary")
	f, err := os.Open("testdata/go-binary")
	require.NoError(t, err)
	defer f.Close()

	cache, err := readatbuf.New(f, 4096, 4)
	require.NoError(t, err)

	ef, err := NewFile(cache, 0, false)
	require.NoError(t, err)

	assert.IsType(t, NoOpCloser{}, ef.Take())
	require.NoError(t, ef.Close())
	// The borrowed reader remains fully functional.
	_, err = cache.ReadAt(make([]byte, 4), 0)
	assert.NoError(t, err)
}

// TestFileBorrowedMappingTake verifies that a File built on a caller-created
// memory mapping borrows it: Close does not unmap it, and it stays usable.
func TestFileBorrowedMappingTake(t *testing.T) {
	testsupport.RequireGeneratedTestFile(t, "testdata/go-binary")
	mapping, err := mmap.Open("testdata/go-binary")
	require.NoError(t, err)
	defer mapping.Close()

	ef, err := NewFile(mapping, 0, false)
	require.NoError(t, err)

	assert.IsType(t, NoOpCloser{}, ef.Take())
	require.NoError(t, ef.Close())
	// The File must not unmap a mapping it does not own.
	view, err := mapping.ViewAt(0, 1)
	require.NoError(t, err)
	assert.NotEmpty(t, view)
}

// elfFixture builds a minimal ELF64 object with a .symtab of the given
// symbol names.
func elfFixture(t *testing.T, names []string) []byte {
	t.Helper()
	type ehdr struct {
		Ident                      [16]byte
		Type, Machine              uint16
		Version                    uint32
		Entry, Phoff, Shoff        uint64
		Flags                      uint32
		Ehsize, Phentsize, Phnum   uint16
		Shentsize, Shnum, Shstrndx uint16
	}
	type phdr struct {
		Type, Flags                      uint32
		Off, Vaddr, Paddr, Filesz, Memsz uint64
		Align                            uint64
	}
	type shdr struct {
		Name, Type         uint32
		Flags              uint64
		Addr, Offset, Size uint64
		Link, Info         uint32
		Align, Entsize     uint64
	}

	shstrtab := []byte{0}
	shname := map[string]uint32{}
	for _, name := range []string{".symtab", ".strtab", ".shstrtab"} {
		shname[name] = uint32(len(shstrtab))
		shstrtab = append(shstrtab, name...)
		shstrtab = append(shstrtab, 0)
	}

	strtab := []byte{0}
	symNameOffs := make([]uint32, len(names))
	for i, name := range names {
		symNameOffs[i] = uint32(len(strtab))
		strtab = append(strtab, name...)
		strtab = append(strtab, 0)
	}

	// Layout: ehdr, phdr, strtab, symtab, shstrtab, section headers.
	symtabOff := 120 + len(strtab)
	symtabSize := (len(names) + 1) * 24
	shstrtabOff := symtabOff + symtabSize
	shoff := shstrtabOff + len(shstrtab)

	var buf bytes.Buffer
	hdr := ehdr{
		Type:      uint16(elf.ET_REL),
		Machine:   uint16(elf.EM_X86_64),
		Version:   1,
		Phoff:     64,
		Shoff:     uint64(shoff),
		Ehsize:    64,
		Phentsize: 56,
		Phnum:     1,
		Shentsize: 64,
		Shnum:     4,
		Shstrndx:  3,
	}
	copy(hdr.Ident[:], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1, 0})
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &hdr))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &phdr{}))
	buf.Write(strtab)
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, elf.Sym64{}))
	for _, nameOff := range symNameOffs {
		require.NoError(t, binary.Write(&buf, binary.LittleEndian, elf.Sym64{
			Name: nameOff, Info: byte(elf.STB_GLOBAL)<<4 | byte(elf.STT_FUNC), Shndx: 1,
		}))
	}
	buf.Write(shstrtab)
	require.Equal(t, shoff, buf.Len())
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &shdr{}))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &shdr{
		Name: shname[".symtab"], Type: uint32(elf.SHT_SYMTAB),
		Offset: uint64(symtabOff), Size: uint64(symtabSize),
		Link: 2, Info: 1, Align: 8, Entsize: 24,
	}))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &shdr{
		Name: shname[".strtab"], Type: uint32(elf.SHT_STRTAB),
		Offset: 120, Size: uint64(len(strtab)),
	}))
	require.NoError(t, binary.Write(&buf, binary.LittleEndian, &shdr{
		Name: shname[".shstrtab"], Type: uint32(elf.SHT_STRTAB),
		Offset: uint64(shstrtabOff), Size: uint64(len(shstrtab)),
	}))
	return buf.Bytes()
}

func TestVisitSymbolsLongNames(t *testing.T) {
	// A name longer than the 4 KiB assembly buffer is skipped: the walk
	// must continue with the remaining symbols.
	longName := strings.Repeat("L", 5000)
	ef, err := NewFile(bytes.NewReader(elfFixture(t, []string{longName, "main"})), 0, false)
	require.NoError(t, err)
	defer ef.Close()

	var names []string
	err = ef.VisitSymbols(func(sym libpf.Symbol) bool {
		names = append(names, string(sym.Name))
		return true
	})
	require.NoError(t, err)
	require.Equal(t, []string{"", "main"}, names)
}
