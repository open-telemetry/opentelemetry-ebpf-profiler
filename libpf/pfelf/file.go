// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// package pfelf implements functions for processing of ELF files and extracting data from
// them. This file implements an independent ELF parser from debug.elf with different usage:
//   - optimized for speed (and supports only ELF files for current CPU architecture)
//   - loads only portions of the ELF really needed and accessed (minimizing CPU/RSS)
//   - can handle partial ELF files without sections present
//   - implements fast symbol lookup using gnu/sysv hashes
//   - coredump notes parsing

// The Executable and Linking Format (ELF) specification is available at:
//   https://refspecs.linuxfoundation.org/elf/elf.pdf
//
// Other extensions we support are not well documented, but the following blog posts
// contain useful information about them:
//   - DT_GNU_HASH symbol index:  https://flapenguin.me/elf-dt-gnu-hash
//   - NT_FILE coredump mappings: https://www.gabriel.urdhr.fr/2015/05/29/core-file/

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const (
	// maxBytesSmallSection is the maximum section size for small libpf
	// parsed sections (e.g. notes and debug link)
	maxBytesSmallSection = 4 * 1024

	// maxBytesLargeSection is the maximum section size for large libpf
	// parsed sections (e.g. symbol tables and string tables; libxul
	// has about 4MB .dynstr)
	maxBytesLargeSection = 16 * 1024 * 1024

	// notYetProcessed is an internal placeholder to mark not yet parsed data.
	notYetProcessed = "\x01"
)

// List of public errors.
var (
	// ErrNotELF is returned when the file is not an ELF file.
	ErrNotELF = errors.New("not an ELF file")

	// ErrNoDebugLink is returned when debug link does not exist.
	ErrNoDebugLink = errors.New("no debug link")

	// ErrNoBuildID is returned if build ID is not present in notes.
	ErrNoBuildID = errors.New("no build ID")

	// errNoGoBuildinfo is returned when the ELF is not a Go executable.
	errNoGoBuildinfo = errors.New("go buildinfo not found")

	// errNotProcessed is an internal placeholder to mark not yet parsed data.
	errNotProcessed = errors.New("not yet processed")

	// strNotProcessed is an internal placeholder to mark not yet parsed data.
	strNotProcessed = libpf.Intern(notYetProcessed)

	// goBuildInfoMagic is the magic header for Go buildinfo
	goBuildInfoMagic = []byte("\xff Go buildinf:")
)

// File represents an open ELF file
type File struct {
	// closer is called internally when resources for this File are to be released
	closer io.Closer

	// elfReader is the ReadAt implementation used for this File
	elfReader io.ReaderAt

	// mmapReader is the mmap reader for this File if available
	mmapReader *mmap.ReaderAt

	// loadData is a slice of pointers to the PT_LOAD data segments of the ELF.
	loadData []*Prog

	// ROData is a slice of pointers to the read-only data segments of the ELF
	// These are sorted so that segments marked as "read" appear before those
	// marked as "read-execute"
	ROData []*Prog

	// Progs contains the program header
	Progs []Prog

	// Sections contains the program sections if loaded
	Sections []Section

	// neededIndexes contains the string tab indexes for DT_NEEDED tags
	neededIndexes []int64

	// neededIndexes contains the string tab index for DT_SONAME tag (or 0)
	soNameIndex int64

	// elfHeader is the ELF file header
	elfHeader elf.Header64

	// gnuHash contains the DT_GNU_HASH header address and data
	gnuHash struct {
		addr   int64
		header gnuHashHeader
	}

	// sysvHash contains the DT_HASH (SYS-V hash) header address and data
	sysvHash struct {
		addr   int64
		header sysvHashHeader
	}

	// stringsAddr is the virtual address for string table from the Dynamic section
	stringsAddr int64

	// symbolAddr is the virtual address for symbol table from the Dynamic section
	symbolsAddr int64

	// bias is the load bias for ELF files inside core dump
	bias libpf.Address

	// InsideCore indicates that this ELF is mapped from a coredump ELF
	InsideCore bool

	// Fields to mimic elf.debug
	Type    elf.Type
	Machine elf.Machine
	Entry   uint64

	// Path to the debuglink exe,
	// or empty if none exists
	debuglinkPath string

	// Cached notes data
	notesError error
	gnuBuildId string
	goBuildId  string

	// Go build info
	golangVersion libpf.String
	golangCgo     bool
}

var (
	_ io.ReaderAt = &File{}
	_ io.ReaderAt = &Section{}
	_ io.ReaderAt = &Prog{}
)

// sysvHashHeader is the ELF DT_HASH section header
type sysvHashHeader struct {
	numBuckets uint32
	numSymbols uint32
}

// gnuHashHeader is the ELF DT_GNU_HASH section header
type gnuHashHeader struct {
	numBuckets   uint32
	symbolOffset uint32
	bloomSize    uint32
	bloomShift   uint32
}

// Prog represents a program header, and data associated with it
type Prog struct {
	elf.ProgHeader

	// elfReader is the same ReadAt as used for the File
	elfReader io.ReaderAt
}

// Section represents a section header, and data associated with it
type Section struct {
	elf.SectionHeader

	// elfReader is the same ReadAt as used for the File
	elfReader io.ReaderAt
}

// Open opens the named file using os.Open and prepares it for use as an ELF binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	return newFile(f, f, 0, false)
}

// Close closes the File.
func (f *File) Close() (err error) {
	if f.mmapReader != nil {
		f.mmapReader.Close()
	}
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return err
}

// NewFile creates a new ELF file object that borrows the given reader.
func NewFile(r io.ReaderAt, loadAddress uint64, hasMusl bool) (*File, error) {
	return newFile(r, nil, loadAddress, hasMusl)
}

// ReadAtCloser combines io.ReaderAt and io.Closer.
type ReadAtCloser interface {
	io.ReaderAt
	io.Closer
}

// NewFileOwned is like NewFile but takes ownership of rc: rc is used as the
// ELF reader and is closed by the returned File's Close, or before returning
// on error.
func NewFileOwned(rc ReadAtCloser) (*File, error) {
	return newFile(rc, rc, 0, false)
}

// newFile builds a File from r. A non-nil closer is owned and closed by the
// returned File's Close, or before returning on error.
func newFile(r io.ReaderAt, closer io.Closer,
	loadAddress uint64, hasMusl bool,
) (*File, error) {
	f := &File{
		elfReader:     r,
		InsideCore:    loadAddress != 0,
		closer:        closer,
		debuglinkPath: notYetProcessed,
		notesError:    errNotProcessed,
		golangVersion: strNotProcessed,
	}
	success := false
	defer func() {
		if !success {
			_ = f.Close()
		}
	}()

	hdr := &f.elfHeader
	if _, err := r.ReadAt(pfunsafe.FromPointer(hdr), 0); err != nil {
		return nil, err
	}
	if !bytes.Equal(hdr.Ident[0:4], []byte{0x7f, 'E', 'L', 'F'}) {
		return nil, ErrNotELF
	}
	if elf.Class(hdr.Ident[elf.EI_CLASS]) != elf.ELFCLASS64 ||
		elf.Data(hdr.Ident[elf.EI_DATA]) != elf.ELFDATA2LSB ||
		elf.Version(hdr.Ident[elf.EI_VERSION]) != elf.EV_CURRENT {
		return nil, fmt.Errorf("unsupported ELF file: %v", hdr.Ident)
	}

	// fill the Machine and Type fields
	f.Machine = elf.Machine(hdr.Machine)
	f.Type = elf.Type(hdr.Type)
	f.Entry = hdr.Entry

	// if number of program headers is 0 this is likely not the ELF file we
	// are interested in
	if hdr.Phnum == 0 {
		return nil, fmt.Errorf("ELF with zero Program headers (type: %v)", hdr.Type)
	}

	progs := make([]elf.Prog64, hdr.Phnum)
	if _, err := r.ReadAt(pfunsafe.FromSlice(progs), int64(hdr.Phoff)); err != nil {
		return nil, err
	}

	if osFile, ok := r.(*os.File); ok {
		// Attempt to mmap the file if possible
		f.mmapReader, _ = mmap.OpenFile(osFile)
	}

	f.Progs = make([]Prog, hdr.Phnum)
	virtualBase := ^uint64(0)
	numROData := 0
	numLoad := 0
	for i, ph := range progs {
		p := &f.Progs[i]
		p.ProgHeader = elf.ProgHeader{
			Type:   elf.ProgType(ph.Type),
			Flags:  elf.ProgFlag(ph.Flags),
			Off:    ph.Off,
			Vaddr:  ph.Vaddr,
			Paddr:  ph.Paddr,
			Filesz: ph.Filesz,
			Memsz:  ph.Memsz,
			Align:  ph.Align,
		}
		p.elfReader = f.getReader()

		if p.Type == elf.PT_LOAD {
			if p.Vaddr < virtualBase {
				virtualBase = p.Vaddr
			}
			if p.isRoData() {
				numROData++
			}
			numLoad++
		}
	}
	f.loadData = make([]*Prog, 0, numLoad)
	f.ROData = make([]*Prog, 0, numROData)
	for i := range progs {
		p := &f.Progs[i]
		if p.Type == elf.PT_LOAD {
			f.loadData = append(f.loadData, p)
			if p.isRoData() {
				f.ROData = append(f.ROData, p)
			}
		}
	}

	if loadAddress != 0 {
		// Calculate the bias for coredump files
		f.bias = libpf.Address(loadAddress - virtualBase)
	}

	// We sort the ROData so that we preferentially access those that are marked
	// as "read" before we access those that are written as "read-execute"
	slices.SortFunc(f.ROData, func(a, b *Prog) int {
		// The &'s here are just in case one segment has PF_MASK_PROC set
		return int(a.Flags&(elf.PF_R|elf.PF_X)) - int(b.Flags&(elf.PF_R|elf.PF_X))
	})

	for i := range f.Progs {
		p := &f.Progs[i]
		if p.Filesz <= 0 {
			continue
		}
		switch p.ProgHeader.Type {
		case elf.PT_DYNAMIC:
			rdr := pfbufio.NewReader(r, int64(p.Off), int64(p.Filesz))

			var dyn elf.Dyn64
			var bias int64
			if !hasMusl {
				// glibc adjusts the PT_DYNAMIC table to contain
				// the mapped virtual addresses. Convert them back
				// to file virtual addresses.
				bias = int64(f.bias)
			}
			for {
				if _, err := rdr.Read(pfunsafe.FromPointer(&dyn)); err != nil {
					break
				}
				adjustedVal := int64(dyn.Val)
				if adjustedVal >= bias {
					adjustedVal -= bias
				}
				switch elf.DynTag(dyn.Tag) {
				case elf.DT_NEEDED:
					f.neededIndexes = append(f.neededIndexes, int64(dyn.Val))
				case elf.DT_SONAME:
					f.soNameIndex = int64(dyn.Val)
				case elf.DT_HASH:
					f.sysvHash.addr = adjustedVal
				case elf.DT_STRTAB:
					f.stringsAddr = adjustedVal
				case elf.DT_SYMTAB:
					f.symbolsAddr = adjustedVal
				case elf.DT_GNU_HASH:
					f.gnuHash.addr = adjustedVal
				}
			}
			pfbufio.PutReader(rdr)
		}
	}

	success = true
	return f, nil
}

// getString extracts a null terminated string from an ELF string table
func getString(section []byte, start int) (string, bool) {
	if start < 0 || start >= len(section) {
		return "", false
	}
	slen := bytes.IndexByte(section[start:], 0)
	if slen < 0 {
		return "", false
	}
	return string(section[start : start+slen]), true
}

// NoMmapCloser is a no-op io.Closer which is returned from Take() when
// the File is not memory mapped.
type NoMmapCloser libpf.Void

// Close implements io.Closer interface.
func (_ NoMmapCloser) Close() error {
	return nil
}

// Take takes a reference on the backing mmapped data. This allows callers to
// keep slices returned by Section.Data() and Prog.Data() after File has been
// GCd. The returned Close() will release the reference on data.
func (f *File) Take() io.Closer {
	if f.mmapReader != nil {
		return f.mmapReader.Take()
	}
	return NoMmapCloser{}
}

// getReader returns the mmap reader if available, or otherwise the underlying
// reader (typically os.File).
func (f *File) getReader() io.ReaderAt {
	if f.mmapReader != nil {
		return f.mmapReader
	}
	return f.elfReader
}

// Underlying returns the underlying io.ReaderAt interface to access the ELF
// file directly.
func (f *File) Underlying() io.ReaderAt {
	return f.elfReader
}

// LoadSections loads the ELF file sections
func (f *File) LoadSections() error {
	if f.InsideCore {
		// Do not look at section headers from ELF inside a coredump. Most
		// notably musl c-library can reuse the section headers area for
		// memory allocator, and this would return garbage.
		return errors.New("section headers are not available for ELF inside coredump")
	}
	if f.Sections != nil {
		// Already loaded.
		return nil
	}

	hdr := &f.elfHeader
	if hdr.Shnum == 0 {
		// No sections. Nothing to do.
		return nil
	}
	if hdr.Shnum > 0 && hdr.Shstrndx >= hdr.Shnum {
		return fmt.Errorf("invalid ELF section string table index (%d / %d)",
			hdr.Shstrndx, hdr.Shnum)
	}

	// Load section headers
	sections := make([]elf.Section64, hdr.Shnum)
	if _, err := f.elfReader.ReadAt(pfunsafe.FromSlice(sections), int64(hdr.Shoff)); err != nil {
		return err
	}

	f.Sections = make([]Section, hdr.Shnum)
	for i, sh := range sections {
		s := &f.Sections[i]
		s.SectionHeader = elf.SectionHeader{
			Type:      elf.SectionType(sh.Type),
			Flags:     elf.SectionFlag(sh.Flags),
			Addr:      sh.Addr,
			Offset:    sh.Off,
			Size:      sh.Size,
			Link:      sh.Link,
			Info:      sh.Info,
			Addralign: sh.Addralign,
			Entsize:   sh.Entsize,
			FileSize:  sh.Size,
		}
		s.elfReader = f.getReader()
	}

	// Load the section name string table
	strsh := f.Sections[hdr.Shstrndx]
	strtab, err := strsh.Data(maxBytesLargeSection)
	if err != nil {
		return err
	}
	for i := range f.Sections {
		sh := &f.Sections[i]
		var ok bool
		sh.Name, ok = getString(strtab, int(sections[i].Name))
		if !ok {
			return fmt.Errorf("bad section name index (section %d, index %d/%d)",
				i, sections[i].Name, len(strtab))
		}
	}

	return nil
}

// findProg finds the first matching program header of given type.
func (f *File) findProg(t elf.ProgType) *Prog {
	for i := range f.Progs {
		if f.Progs[i].Type == t {
			return &f.Progs[i]
		}
	}
	return nil
}

// Section returns a section with the given name, or nil if no such section exists.
func (f *File) Section(name string) *Section {
	if f.InsideCore {
		return nil
	}
	if err := f.LoadSections(); err != nil {
		f.InsideCore = true
		return nil
	}
	for i := range f.Sections {
		s := &f.Sections[i]
		if s.Name == name {
			return s
		}
	}
	return nil
}

// findVirtualAddressProg determines the Prog header containing the virtual address.
func (f *File) findVirtualAddressProg(addr uint64) *Prog {
	// Search for the Program header that contains the start address.
	for _, ph := range f.loadData {
		if addr >= ph.Vaddr && addr < ph.Vaddr+ph.Memsz {
			return ph
		}
	}
	return nil
}

// VirtualMemory returns a slice for the request data at a virtual address.
// The slice may point to mmapped data or be a newly allocated slice.
// The maxSize is the limit for allocating the memory from heap.
func (f *File) VirtualMemory(addr int64, sz, maxSize int) ([]byte, error) {
	if sz == 0 {
		return nil, nil
	}
	if ph := f.findVirtualAddressProg(uint64(addr)); ph != nil {
		offset := addr - int64(ph.Vaddr)
		if offset+int64(sz) <= int64(ph.Filesz) {
			if mapping, ok := ph.elfReader.(*mmap.ReaderAt); ok {
				return mapping.Subslice(int(ph.Off)+int(offset), sz)
			}
		}
		if sz > maxSize {
			return nil, fmt.Errorf("virtual memory area too large (%d) to copy", sz)
		}
		buf := make([]byte, sz)
		n, err := ph.ReadAt(buf, offset)
		return buf[:n], err
	}
	return nil, fmt.Errorf("no matching segment for 0x%x", uint64(addr))
}

// SymbolData reads and returns the data associated with given dynamic symbol.
// The maximum data read is capped to maxSize.
func (f *File) SymbolData(name libpf.SymbolName, maxSize int) (*libpf.Symbol, []byte, error) {
	sym, err := f.LookupSymbol(name)
	if err != nil {
		return nil, nil, err
	}
	data := make([]byte, min(int(sym.Size), maxSize))
	_, err = f.ReadAt(data, int64(sym.Address))
	if err != nil {
		return nil, nil, err
	}
	return sym, data, nil
}

// EHFrame constructs a Program header with the EH Frame sections
func (f *File) EHFrame() (*Prog, error) {
	p := f.findProg(elf.PT_GNU_EH_FRAME)
	if p == nil {
		return nil, errors.New("no PT_GNU_EH_FRAME tag found")
	}
	// Find matching PT_LOAD segment
	for i := range f.Progs {
		ph := &f.Progs[i]
		if ph.Type != elf.PT_LOAD || p.Vaddr < ph.Vaddr ||
			p.Vaddr >= ph.Vaddr+ph.Filesz {
			continue
		}
		// Normally the LOAD segment contains .rodata, .eh_frame_hdr
		// and .eh_frame. Craft a subset segment that contains the data
		// from start of the PT_GNU_EH_FRAME start until end of the LOAD
		// segment.
		offs := p.Vaddr - ph.Vaddr
		return &Prog{
			ProgHeader: elf.ProgHeader{
				Type:   ph.Type,
				Flags:  ph.Flags,
				Off:    ph.Off + offs,
				Vaddr:  ph.Vaddr + offs,
				Paddr:  ph.Paddr + offs,
				Filesz: ph.Filesz - offs,
				Memsz:  ph.Memsz - offs,
				Align:  ph.Align,
			},
			elfReader: f.getReader(),
		}, nil
	}
	return nil, errors.New("no PT_LOAD segment for PT_GNU_EH_FRAME found")
}

// VisitNotes iterates the ELF notes.
// The visitor must make copies of the 'data' it keeps after return.
func (f *File) VisitNotes(visitor func(uint64, []byte) bool) error {
	notes := f.findProg(elf.PT_NOTE)
	if notes == nil {
		return nil
	}

	rdr := pfbufio.NewReader(f.elfReader, int64(notes.Off), int64(notes.Filesz))
	defer pfbufio.PutReader(rdr)

	return visitNotes(rdr, visitor)
}

// parseNotes parses and caches the ELF notes for the File.
func (f *File) parseNotes() error {
	if f.notesError == errNotProcessed {
		f.notesError = f.VisitNotes(func(note uint64, desc []byte) bool {
			switch note {
			case NoteGnuBuildId:
				f.gnuBuildId = hex.EncodeToString(desc)
			case NoteGoBuildId:
				f.goBuildId = string(desc)
			}
			return true
		})
	}
	return f.notesError
}

// GetGoBuildID returns the Go BuildID if present
func (f *File) GetGoBuildID() (string, error) {
	err := f.parseNotes()
	if err == nil && f.goBuildId == "" {
		err = ErrNoBuildID
	}
	return f.goBuildId, err
}

// GetBuildID returns the ELF BuildID if present
func (f *File) GetBuildID() (string, error) {
	err := f.parseNotes()
	if err == nil && f.gnuBuildId == "" {
		err = ErrNoBuildID
	}
	return f.gnuBuildId, err
}

// DebuglinkFileName returns the debug file linked by .gnu_debuglink if any
func (f *File) DebuglinkFileName(elfFilePath string, elfOpener ELFOpener) string {
	if f.debuglinkPath != notYetProcessed {
		return f.debuglinkPath
	}
	file, path := f.OpenDebugLink(elfFilePath, elfOpener)
	if file != nil {
		_ = file.Close()
	}
	return path
}

type ElfReloc = elf.Rela64

// RelocType represents an architecture-independent relocation type.
// Multiple values can be combined with bitwise OR to match several types.
type RelocType uint32

const (
	// RelTLSDESC matches TLSDESC relocations (R_AARCH64_TLSDESC, R_X86_64_TLSDESC).
	RelTLSDESC RelocType = 1 << iota
	// RelDTPMOD64 matches DTPMOD64 relocations (R_AARCH64_TLS_DTPMOD64, R_X86_64_DTPMOD64).
	RelDTPMOD64
)

// classifyRelocAarch64 returns the RelocType for an AARCH64 relocation.
func classifyRelocAarch64(rela ElfReloc) RelocType {
	switch elf.R_AARCH64(rela.Info & 0xffff) {
	case elf.R_AARCH64_TLSDESC:
		return RelTLSDESC
	case elf.R_AARCH64_TLS_DTPMOD64:
		return RelDTPMOD64
	default:
		return 0
	}
}

// classifyRelocX86_64 returns the RelocType for an X86_64 relocation.
func classifyRelocX86_64(rela ElfReloc) RelocType {
	switch elf.R_X86_64(rela.Info & 0xffff) {
	case elf.R_X86_64_TLSDESC:
		return RelTLSDESC
	case elf.R_X86_64_DTPMOD64:
		return RelDTPMOD64
	default:
		return 0
	}
}

// VisitTLSRelocations visits all TLSDESC relocations and provides the relocation
// for the TLS symbol, as well as a best-effort string for the symbol's name.
// It continues until the visitor returns false.
func (f *File) VisitTLSRelocations(visitor func(ElfReloc, string) bool) error {
	return f.VisitRelocations(visitor, RelTLSDESC)
}

// VisitRelocations visits all relocations whose type matches the relTypes
// bitmask and provides the relocation and symbol name to the visitor. The
// visitor can return false to stop iteration.
func (f *File) VisitRelocations(visitor func(ElfReloc, string) bool,
	relTypes RelocType) error {
	var classify func(ElfReloc) RelocType
	switch f.Machine {
	case elf.EM_AARCH64:
		classify = classifyRelocAarch64
	case elf.EM_X86_64:
		classify = classifyRelocX86_64
	default:
		return nil
	}
	filterFunc := func(rela ElfReloc) bool {
		return classify(rela)&relTypes != 0
	}
	var err error
	if err = f.LoadSections(); err != nil {
		return err
	}

	for i := range f.Sections {
		section := &f.Sections[i]
		// NOTE: SHT_REL is not relevant for the archs that we care about
		if section.Type == elf.SHT_RELA {
			cont, err := f.visitRelocationsForSection(visitor, filterFunc, section)
			if err != nil {
				return err
			}
			if !cont {
				return nil
			}
		}
	}

	return nil
}

func (f *File) visitRelocationsForSection(visitor func(ElfReloc, string) bool,
	checkRelocation func(ElfReloc) bool,
	relaSection *Section,
) (bool, error) {
	if relaSection.Link >= uint32(len(f.Sections)) {
		return false, fmt.Errorf("rela section link is invalid (%d/%d)",
			relaSection.Link, len(f.Sections))
	}
	if relaSection.Size%uint64(unsafe.Sizeof(elf.Rela64{})) != 0 {
		return false, errors.New("relocation section size isn't multiple of rela64 struct")
	}

	symtabSection := &f.Sections[relaSection.Link]
	if symtabSection.Link >= uint32(len(f.Sections)) {
		return false, fmt.Errorf("symtab section link is invalid (%d/%d)",
			symtabSection.Link, len(f.Sections))
	}
	if symtabSection.Size%uint64(unsafe.Sizeof(elf.Sym64{})) != 0 {
		return false, errors.New("symbol section size isn't multiple of sym64 struct")
	}

	strtabSection := &f.Sections[symtabSection.Link]
	if strtabSection.Size > maxBytesLargeSection {
		return false, fmt.Errorf("string table too big (%d bytes)", strtabSection.Size)
	}

	strtabData, err := strtabSection.Data(uint(strtabSection.Size))
	if err != nil {
		return false, fmt.Errorf("failed to read string table: %w", err)
	}

	rdr := pfbufio.NewReader(f.elfReader, int64(relaSection.Offset), int64(relaSection.Size))
	defer pfbufio.PutReader(rdr)

	rela := &elf.Rela64{}
	sym := &elf.Sym64{}
	symSz := int64(unsafe.Sizeof(elf.Sym64{}))
	for {
		if _, err := rdr.Read(pfunsafe.FromPointer(rela)); err != nil {
			if err != io.EOF {
				return false, fmt.Errorf("failed to read relocation: %w", err)
			}
			break
		}
		if !checkRelocation(*rela) {
			continue
		}
		symNo := int64(rela.Info >> 32)
		n, err := symtabSection.ReadAt(pfunsafe.FromPointer(sym), symNo*symSz)
		if err != nil || n != int(symSz) {
			return false, fmt.Errorf("failed to read relocation symbol: %w", err)
		}

		symStr, ok := getString(strtabData, int(sym.Name))
		if !ok {
			return false, errors.New("failed to get relocation name string")
		}

		if !visitor(*rela, symStr) {
			return false, nil
		}
	}
	runtime.KeepAlive(f)

	return true, nil
}

// GetDebugLink reads and parses the .gnu_debuglink section.
// If the link does not exist then ErrNoDebugLink is returned.
func (f *File) GetDebugLink() (linkName string, crc int32, err error) {
	s := f.Section(".gnu_debuglink")
	if s == nil {
		return "", 0, ErrNoDebugLink
	}

	rdr := pfbufio.NewReader(f.elfReader, int64(s.Offset), int64(s.Size))
	defer pfbufio.PutReader(rdr)

	d, err := rdr.ReadN(int(s.Size))
	if err != nil {
		return "", 0, fmt.Errorf("unable to read debug link: %w", err)
	}
	return ParseDebugLink(d)
}

// OpenDebugLink tries to locate and open the corresponding debug ELF for this DSO.
func (f *File) OpenDebugLink(elfFilePath string, elfOpener ELFOpener) (
	debugELF *File, debugFile string,
) {
	f.debuglinkPath = ""
	// Get the debug link
	linkName, linkCRC32, err := f.GetDebugLink()
	if err != nil {
		// Treat missing or corrupt tag as soft error.
		return
	}

	// Try to find the debug file
	executablePath := filepath.Dir(elfFilePath)
	for _, debugPath := range []string{"/usr/lib/debug/"} {
		debugFile = filepath.Join(debugPath, executablePath, linkName)
		debugELF, err = elfOpener.OpenELF(debugFile)
		if err != nil {
			continue
		}
		fileCRC32, err := debugELF.CRC32()
		if err != nil || fileCRC32 != linkCRC32 {
			_ = debugELF.Close()
			continue
		}
		f.debuglinkPath = debugFile
		return debugELF, debugFile
	}
	return
}

// CRC32 calculates the .gnu_debuglink compatible CRC-32 of the ELF file
func (f *File) CRC32() (int32, error) {
	h := crc32.NewIEEE()
	sr := io.NewSectionReader(f.elfReader, 0, 1<<63-1)
	if _, err := io.Copy(h, sr); err != nil {
		return 0, fmt.Errorf("unable to compute CRC32: %v (failed copy)", err)
	}
	return int32(h.Sum32()), nil
}

// isRoData determine if this program header is read-only data.
func (ph *Prog) isRoData() bool {
	if ph.Type != elf.PT_LOAD {
		return false
	}
	andFlags := ph.Flags & (elf.PF_R | elf.PF_W | elf.PF_X)
	return andFlags == elf.PF_R || andFlags == (elf.PF_R|elf.PF_X)
}

// ReadAt implements the io.ReaderAt interface
func (ph *Prog) ReadAt(p []byte, off int64) (n int, err error) {
	// First load as much as possible from the disk
	if uint64(off) < ph.Filesz {
		end := int(min(int64(len(p)), int64(ph.Filesz)-off))
		n, err = ph.elfReader.ReadAt(p[0:end], int64(ph.Off)+off)
		if n == 0 && errors.Is(err, syscall.EFAULT) {
			// Read zeroes from sparse file holes
			for i := range p[0:end] {
				p[i] = 0
			}
			n = end
		}
		if n != end || err != nil {
			return n, err
		}
		off += int64(n)
	}

	// The gap between Filesz and Memsz is allocated by dynamic loader as
	// anonymous pages, and zero initialized. Read zeroes from this area.
	if n < len(p) && uint64(off) < ph.Memsz {
		end := int(min(int64(len(p)-n), int64(ph.Memsz)-off))
		for i := range p[n : n+end] {
			p[i] = 0
		}
		n += end
	}

	if n != len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Data loads the whole program header referenced data, and returns it as slice.
func (ph *Prog) Data(maxSize uint) ([]byte, error) {
	if mapping, ok := ph.elfReader.(*mmap.ReaderAt); ok {
		return mapping.Subslice(int(ph.Off), int(ph.Filesz))
	}

	// Fallback option if the file is not mmapped.
	if ph.Filesz > uint64(maxSize) {
		return nil, fmt.Errorf("segment size %d is too large", ph.Filesz)
	}
	p := make([]byte, ph.Filesz)
	_, err := ph.ReadAt(p, 0)
	return p, err
}

// ReadAt implements the io.ReaderAt interface
func (sh *Section) ReadAt(p []byte, off int64) (n int, err error) {
	if off < 0 || uint64(off) >= sh.FileSize {
		return 0, io.EOF
	}
	truncated := false
	if uint64(off)+uint64(len(p)) > sh.FileSize {
		p = p[:sh.FileSize-uint64(off)]
		truncated = true
	}
	n, err = sh.elfReader.ReadAt(p, off+int64(sh.Offset))
	if err == nil && truncated {
		err = io.EOF
	}
	return n, err
}

// Data loads the whole section header referenced data, and returns it as a slice.
func (sh *Section) Data(maxSize uint) ([]byte, error) {
	if sh.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, errors.New("compressed sections not supported")
	}

	if mapping, ok := sh.elfReader.(*mmap.ReaderAt); ok {
		return mapping.Subslice(int(sh.Offset), int(sh.FileSize))
	}

	// Fallback option if the file is not mmapped.
	if sh.FileSize > uint64(maxSize) {
		return nil, fmt.Errorf("section size %d is too large", sh.FileSize)
	}
	p := make([]byte, sh.FileSize)
	_, err := sh.ReadAt(p, 0)
	return p, err
}

// SetDontNeed sets the flag MADV_DONTNEED on the mmapped data.
func (f *File) SetDontNeed() {
	if f.mmapReader != nil {
		if err := f.mmapReader.SetMadvDontNeed(); err != nil {
			log.Errorf("Failed to set MADV_DONTNEED: %v", err)
		}
	}
}

// ReadAt reads bytes from given virtual address
func (f *File) ReadAt(p []byte, addr int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if ph := f.findVirtualAddressProg(uint64(addr)); ph != nil {
		return ph.ReadAt(p, addr-int64(ph.Vaddr))
	}
	return 0, fmt.Errorf("no matching segment for 0x%x", uint64(addr))
}

// GetRemoteMemory returns RemoteMemory interface for the core dump
func (f *File) GetRemoteMemory() remotememory.RemoteMemory {
	return remotememory.RemoteMemory{
		ReaderAt: f,
		Bias:     f.bias,
	}
}

// readAndMatchSymbol reads symbol table data expecting given symbol
func (f *File) readAndMatchSymbol(n uint32, name libpf.SymbolName) (libpf.Symbol, bool) {
	var sym elf.Sym64

	// Read symbol descriptor and expected name
	symSz := int64(unsafe.Sizeof(sym))
	if _, err := f.ReadAt(pfunsafe.FromPointer(&sym),
		f.symbolsAddr+int64(n)*symSz); err != nil {
		return libpf.Symbol{}, false
	}
	slen := len(name)
	sname, err := f.VirtualMemory(f.stringsAddr+int64(sym.Name), slen+1, maxBytesSmallSection)
	if err != nil {
		return libpf.Symbol{}, false
	}

	// Verify that name matches
	if sname[slen] != 0 || pfunsafe.ToString(sname[:slen]) != string(name) {
		return libpf.Symbol{}, false
	}

	return libpf.Symbol{
		Name:    name,
		Address: libpf.SymbolValue(sym.Value),
		Size:    sym.Size,
	}, true
}

// calcGNUHash calculates a GNU symbol hash
func calcGNUHash(s libpf.SymbolName) uint32 {
	h := uint32(5381)
	for _, c := range []byte(s) {
		h += h*32 + uint32(c)
	}
	return h
}

// calcSysvHash calculates a sysv symbol hash
func calcSysvHash(s libpf.SymbolName) uint32 {
	h := uint32(0)
	for _, c := range []byte(s) {
		h = 16*h + uint32(c)
		h ^= h >> 24 & 0xf0
	}
	return h & 0xfffffff
}

// LookupSymbol searches for a given symbol in the ELF
func (f *File) LookupSymbol(symbol libpf.SymbolName) (*libpf.Symbol, error) {
	if f.gnuHash.addr != 0 {
		// Standard DT_GNU_HASH lookup code follows. Please check the DT_GNU_HASH
		// blog link (on top of this file) for details how this works.
		hdr := &f.gnuHash.header
		if hdr.numBuckets == 0 {
			if _, err := f.ReadAt(pfunsafe.FromPointer(hdr), f.gnuHash.addr); err != nil {
				return nil, err
			}
			if hdr.numBuckets == 0 || hdr.bloomSize == 0 {
				return nil, errors.New("DT_GNU_HASH corrupt")
			}
		}
		ptrSize := int64(unsafe.Sizeof(uint(0)))
		ptrSizeBits := uint32(8 * ptrSize)

		// First check the Bloom filter if the symbol exists in the hash table or not.
		var bloom uint
		h := calcGNUHash(symbol)
		offs := f.gnuHash.addr + int64(unsafe.Sizeof(gnuHashHeader{}))
		if _, err := f.ReadAt(pfunsafe.FromPointer(&bloom), offs+
			ptrSize*int64((h/ptrSizeBits)%hdr.bloomSize)); err != nil {
			return nil, err
		}
		mask := uint(1)<<(h%ptrSizeBits) |
			uint(1)<<((h>>hdr.bloomShift)%ptrSizeBits)
		if bloom&mask != mask {
			return nil, libpf.ErrSymbolNotFound
		}

		// Read the initial symbol index to start looking from
		offs += int64(hdr.bloomSize) * int64(unsafe.Sizeof(bloom))
		var i uint32
		if _, err := f.ReadAt(pfunsafe.FromPointer(&i),
			offs+4*int64(h%hdr.numBuckets)); err != nil {
			return nil, err
		}
		if i == 0 {
			return nil, libpf.ErrSymbolNotFound
		}

		// Search the hash bucket
		offs += 4*int64(hdr.numBuckets) + 4*int64(i-hdr.symbolOffset)
		h |= 1
		for {
			var h2 uint32
			if _, err := f.ReadAt(pfunsafe.FromPointer(&h2), offs); err != nil {
				return nil, err
			}
			// Do a full match of the symbol if the symbol hash matches
			if h == h2|1 {
				if s, ok := f.readAndMatchSymbol(i, symbol); ok {
					return &s, nil
				}
			}
			// Was this last entry in the bucket?
			if h2&1 != 0 {
				break
			}
			offs += 4
			i++
		}
	} else if f.sysvHash.addr != 0 {
		// Normal ELF symbol lookup. Refer to ELF spec, part 2 "Hash Table" (2-19)
		hdr := &f.sysvHash.header
		if hdr.numBuckets == 0 {
			if _, err := f.ReadAt(pfunsafe.FromPointer(hdr), f.sysvHash.addr); err != nil {
				return nil, err
			}
			if hdr.numBuckets == 0 {
				return nil, errors.New("DT_HASH corrupt")
			}
		}
		var i uint32
		offs := f.sysvHash.addr + int64(unsafe.Sizeof(*hdr))
		h := calcSysvHash(symbol)
		bucket := int64(h % hdr.numBuckets)
		if _, err := f.ReadAt(pfunsafe.FromPointer(&i), offs+4*bucket); err != nil {
			return nil, err
		}
		offs += 4 * int64(hdr.numBuckets)
		for i != 0 && i < hdr.numSymbols {
			if s, ok := f.readAndMatchSymbol(i, symbol); ok {
				return &s, nil
			}
			if _, err := f.ReadAt(pfunsafe.FromPointer(&i), offs+4*int64(i)); err != nil {
				return nil, err
			}
		}
	} else {
		return nil, errors.New("symbol hash not present")
	}

	return nil, libpf.ErrSymbolNotFound
}

// LookupSymbol searches for a given symbol in the ELF
func (f *File) LookupSymbolAddress(symbol libpf.SymbolName) (libpf.SymbolValue, error) {
	s, err := f.LookupSymbol(symbol)
	if err != nil {
		return libpf.SymbolValueInvalid, err
	}
	return s.Address, nil
}

// visitSymbolTable visits all symbols in the given symbol table.
func (f *File) visitSymbolTable(name string, visitor func(libpf.Symbol) bool) error {
	symTab := f.Section(name)
	if symTab == nil {
		return fmt.Errorf("failed to read %v: section not present", name)
	}
	if symTab.Link >= uint32(len(f.Sections)) {
		return fmt.Errorf("failed to read %v strtab: link %v out of range",
			name, symTab.Link)
	}
	strTab := f.Sections[symTab.Link]
	strs, err := strTab.Data(maxBytesLargeSection)
	if err != nil {
		return fmt.Errorf("failed to read %v: %v", strTab.Name, err)
	}

	rdr := pfbufio.NewReader(f.elfReader, int64(symTab.Offset), int64(symTab.Size))
	defer pfbufio.PutReader(rdr)

	sym := &elf.Sym64{}
	for {
		if _, err := rdr.Read(pfunsafe.FromPointer(sym)); err != nil {
			if err != io.EOF {
				return fmt.Errorf("failed to read symbol from %v: %w", name, err)
			}
			break
		}
		if name, ok := getString(strs, int(sym.Name)); ok {
			if !visitor(libpf.Symbol{
				Name:    libpf.SymbolName(name),
				Address: libpf.SymbolValue(sym.Value),
				Size:    sym.Size,
			}) {
				break
			}
		}
	}
	runtime.KeepAlive(f)
	return nil
}

// VisitSymbols iterates through the symbol table until visitor returns false.
func (f *File) VisitSymbols(visitor func(libpf.Symbol) bool) error {
	return f.visitSymbolTable(".symtab", visitor)
}

// VisitDynamicSymbols iterates through the dynamic symbol table until visitor returns false.
func (f *File) VisitDynamicSymbols(visitor func(libpf.Symbol) bool) error {
	return f.visitSymbolTable(".dynsym", visitor)
}

// DynString returns the strings listed for the given tag in the file's dynamic
// program header.
func (f *File) DynString(tag elf.DynTag) ([]string, error) {
	var indexes []int64
	switch tag {
	case elf.DT_NEEDED:
		indexes = f.neededIndexes
	case elf.DT_SONAME:
		indexes = []int64{f.soNameIndex}
	case elf.DT_RPATH, elf.DT_RUNPATH:
		return nil, fmt.Errorf("unsupported tag %v", tag)
	default:
		return nil, fmt.Errorf("non-string-valued tag %v", tag)
	}

	rm := f.GetRemoteMemory()
	dynStrings := make([]string, 0, len(indexes))
	for _, ndx := range indexes {
		strAddr := libpf.Address(f.stringsAddr + ndx)
		dynStrings = append(dynStrings, rm.String(strAddr))
	}
	return dynStrings, nil
}

// IsGolang determines if this ELF is a Golang executable
func (f *File) IsGolang() bool {
	if _, err := f.GetGoBuildID(); err == nil {
		return true
	}
	return f.Section(".go.buildinfo") != nil || f.Section(".gopclntab") != nil
}

func decodeString(rdr *pfbufio.Reader) (string, error) {
	b, err := rdr.Peek(binary.MaxVarintLen64)
	if err != nil {
		return "", err
	}
	size, n := binary.Uvarint(b)
	if n <= 0 || size >= maxBytesSmallSection {
		return "", errNoGoBuildinfo
	}
	rdr.Discard(int(n))
	return rdr.ReadStringN(int(size))
}

func readString(r io.ReaderAt, addr uint64) (string, error) {
	var addrAndSize [16]byte

	if _, err := r.ReadAt(addrAndSize[:], int64(addr)); err != nil {
		return "", err
	}
	addr = binary.LittleEndian.Uint64(addrAndSize[0:])
	size := binary.LittleEndian.Uint64(addrAndSize[8:])
	if size >= maxBytesSmallSection {
		return "", errNoGoBuildinfo
	}

	val := make([]byte, size)
	_, err := r.ReadAt(val, int64(addr))
	return pfunsafe.ToString(val), err
}

func extractGolangSettings(mod string) bool {
	if len(mod) <= 32 || mod[len(mod)-17] != '\n' {
		// Does not look like valid module frame.
		return false
	}
	// Remove the module frame
	mod = mod[16 : len(mod)-16]

	for len(mod) > 0 {
		line := mod
		if nl := strings.Index(mod, "\n"); nl >= 0 {
			line = mod[:nl]
			mod = mod[nl+1:]
		} else {
			mod = mod[0:0]
		}
		if line == "build\tCGO_ENABLED=1" {
			return true
		}
	}
	return false
}

func (f *File) parseGoBuildinfo() error {
	if f.golangVersion != strNotProcessed {
		return nil
	}
	f.golangVersion = libpf.NullString

	var off, sz int64
	if s := f.Section(".go.buildinfo"); s != nil {
		off = int64(s.Offset)
		sz = int64(s.Size)
	} else {
		if !f.IsGolang() {
			return nil
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_LOAD && p.Flags&(elf.PF_X|elf.PF_W) == elf.PF_W {
				off = int64(p.Off)
				sz = int64(p.Filesz)
				break
			}
		}
	}
	if sz == 0 {
		return nil
	}

	rdr := pfbufio.NewReader(f.Underlying(), off, sz)
	defer pfbufio.PutReader(rdr)

	for {
		offset, err := rdr.SearchSlice(goBuildInfoMagic)
		if err != nil {
			return errNoGoBuildinfo
		}
		if offset%16 == 0 {
			break
		}
	}

	// type buildInfoHeader struct {
	// 	magic       [14]byte
	// 	ptrSize     uint8 // used if flagsVersionPtr
	// 	flags       uint8
	// 	versPtr     targetUintptr // used if flagsVersionPtr
	// 	modPtr      targetUintptr // used if flagsVersionPtr
	// }
	ptrSize, err := rdr.ReadByte()
	if err != nil {
		return errNoGoBuildinfo
	}
	flags, err := rdr.ReadByte()
	if err != nil {
		return errNoGoBuildinfo
	}
	if flags&2 != 0 {
		// Go 1.18+ inline strings
		_, err = rdr.Discard(16)
		if err != nil {
			return errNoGoBuildinfo
		}
		ver, err := decodeString(rdr)
		if err != nil {
			return err
		}
		f.golangVersion = libpf.Intern(ver)

		mod, err := decodeString(rdr)
		if err != nil {
			return err
		}
		f.golangCgo = extractGolangSettings(mod)
	} else {
		// Go <1.18 with string pointers
		ptrs, err := rdr.ReadN(16)
		if err != nil {
			return errNoGoBuildinfo
		}
		// Only 64-bit little-endian is supported
		if ptrSize != 8 || flags&1 != 0 {
			return fmt.Errorf("pointers with size %d, flags %x not supported",
				ptrSize, flags)
		}
		verPtr := binary.LittleEndian.Uint64(ptrs[0:])
		modPtr := binary.LittleEndian.Uint64(ptrs[8:])

		ver, err := readString(f, verPtr)
		if err != nil {
			return err
		}
		f.golangVersion = libpf.Intern(ver)

		mod, err := readString(f, modPtr)
		if err != nil {
			return err
		}
		f.golangCgo = extractGolangSettings(mod)
	}
	return nil
}

// GoVersion returns the Go version if present and empty string otherwise.
func (f *File) GoVersion() string {
	if err := f.parseGoBuildinfo(); err != nil {
		log.Debugf("Failed to read go buildinfo: %v", err)
	}
	return f.golangVersion.String()
}

func (f *File) IsCgoEnabled() bool {
	if err := f.parseGoBuildinfo(); err != nil {
		log.Debugf("Failed to read go buildinfo: %v", err)
	}
	return f.golangCgo
}
