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
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/readatbuf"
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
)

// ErrSymbolNotFound is returned when requested symbol was not found
var ErrSymbolNotFound = errors.New("symbol not found")

// ErrNotELF is returned when the file is not an ELF
var ErrNotELF = errors.New("not an ELF file")

// File represents an open ELF file
type File struct {
	// closer is called internally when resources for this File are to be released
	closer io.Closer

	// elfReader is the ReadAt implementation used for this File
	elfReader io.ReaderAt

	// ehFrame is a pointer to the PT_GNU_EH_FRAME segment of the ELF
	ehFrame *Prog

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
	// Whether we have checked for a debuglink
	debuglinkChecked bool
}

var _ libpf.SymbolFinder = &File{}

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

	// Embed ReaderAt for ReadAt method.
	io.ReaderAt

	// Do not embed SectionReader directly, or as public member. We can't
	// return the same copy to multiple callers, otherwise they corrupt
	// each other's reader file position.
	sr *io.SectionReader
}

// Open opens the named file using os.Open and prepares it for use as an ELF binary.
func Open(name string) (*File, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}

	// Wrap it in a cacher as we often do short reads
	buffered, err := readatbuf.New(f, 1024, 4)
	if err != nil {
		return nil, err
	}

	ff, err := newFile(buffered, f, 0, false)
	if err != nil {
		f.Close()
		return nil, err
	}
	return ff, nil
}

// Close closes the File.
func (f *File) Close() (err error) {
	if f.closer != nil {
		err = f.closer.Close()
		f.closer = nil
	}
	return
}

// NewFile creates a new ELF file object that borrows the given reader.
func NewFile(r io.ReaderAt, loadAddress uint64, hasMusl bool) (*File, error) {
	return newFile(r, nil, loadAddress, hasMusl)
}

func newFile(r io.ReaderAt, closer io.Closer, loadAddress uint64, hasMusl bool) (*File, error) {
	f := &File{
		elfReader:  r,
		InsideCore: loadAddress != 0,
		closer:     closer,
	}

	hdr := &f.elfHeader
	if _, err := r.ReadAt(libpf.SliceFrom(hdr), 0); err != nil {
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
	if _, err := r.ReadAt(libpf.SliceFrom(progs), int64(hdr.Phoff)); err != nil {
		return nil, err
	}

	f.Progs = make([]Prog, hdr.Phnum)
	virtualBase := ^uint64(0)
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
		p.elfReader = r

		if p.Type == elf.PT_LOAD {
			if p.Vaddr < virtualBase {
				virtualBase = p.Vaddr
			}
			andFlags := p.Flags & (elf.PF_R | elf.PF_W | elf.PF_X)
			if andFlags == elf.PF_R || andFlags == (elf.PF_R|elf.PF_X) {
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
	sort.Slice(f.ROData, func(i, j int) bool {
		// The &'s here are just in case one segment has PF_MASK_PROC set
		return f.ROData[i].Flags&(elf.PF_R|elf.PF_X) <
			f.ROData[j].Flags&(elf.PF_R|elf.PF_X)
	})

	for i := range f.Progs {
		p := &f.Progs[i]
		if p.Filesz <= 0 {
			continue
		}
		switch p.ProgHeader.Type {
		case elf.PT_DYNAMIC:
			rdr, err := p.DataReader(maxBytesLargeSection)
			if err != nil {
				continue
			}
			var dyn elf.Dyn64
			var bias int64
			if !hasMusl {
				// glibc adjusts the PT_DYNAMIC table to contain
				// the mapped virtual addresses. Convert them back
				// to file virtual addresses.
				bias = int64(f.bias)
			}
			for {
				if _, err := rdr.Read(libpf.SliceFrom(&dyn)); err != nil {
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
		case elf.PT_GNU_EH_FRAME:
			f.ehFrame = p
		}
	}

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
	if _, err := f.elfReader.ReadAt(libpf.SliceFrom(sections), int64(hdr.Shoff)); err != nil {
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
		s.sr = io.NewSectionReader(f.elfReader, int64(s.Offset), int64(s.FileSize))
		s.ReaderAt = s.sr
	}

	// Load the section name string table
	strsh := f.Sections[hdr.Shstrndx]
	if strsh.FileSize >= 1024*1024 {
		return fmt.Errorf("section headers string table too large (%d)",
			strsh.FileSize)
	}
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

// ReadVirtualMemory reads bytes from given virtual address
func (f *File) ReadVirtualMemory(p []byte, addr int64) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for _, ph := range f.Progs {
		// Search for the Program header that contains the start address.
		// ReadVirtualMemory() supports ReadAt() style indication of reading
		// less bytes then requested, so addr+len(p) can be an address beyond
		// the segment and ReadAt() will give short read.
		if ph.Type == elf.PT_LOAD && uint64(addr) >= ph.Vaddr &&
			uint64(addr) < ph.Vaddr+ph.Memsz {
			return ph.ReadAt(p, addr-int64(ph.Vaddr))
		}
	}
	return 0, fmt.Errorf("no matching segment for 0x%x", uint64(addr))
}

// EHFrame constructs a Program header with the EH Frame sections
func (f *File) EHFrame() (*Prog, error) {
	if f.ehFrame == nil {
		return nil, errors.New("no PT_GNU_EH_FRAME tag found")
	}
	// Find matching PT_LOAD segment
	p := f.ehFrame
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
			elfReader: f.elfReader,
		}, nil
	}
	return nil, errors.New("no PT_LOAD segment for PT_GNU_EH_FRAME found")
}

// GetBuildID returns the ELF BuildID if present
func (f *File) GetBuildID() (string, error) {
	s := f.Section(".note.gnu.build-id")
	if s == nil {
		s = f.Section(".notes")
	}
	if s == nil {
		return "", ErrNoBuildID
	}
	data, err := s.Data(maxBytesSmallSection)
	if err != nil {
		return "", err
	}

	return getBuildIDFromNotes(data)
}

// DebuglinkFileName returns the debug file linked by .gnu_debuglink if any
func (f *File) DebuglinkFileName(elfFilePath string, elfOpener ELFOpener) string {
	if f.debuglinkChecked {
		return f.debuglinkPath
	}
	file, path := f.OpenDebugLink(elfFilePath, elfOpener)
	if file != nil {
		file.Close()
	}
	return path
}

// TLSDescriptors returns a map of all TLS descriptor symbol -> address
// mappings in the executable.
func (f *File) TLSDescriptors() (map[string]libpf.Address, error) {
	var err error
	if err = f.LoadSections(); err != nil {
		return nil, err
	}

	descs := make(map[string]libpf.Address)
	for i := range f.Sections {
		section := &f.Sections[i]
		// NOTE: SHT_REL is not relevant for the archs that we care about
		if section.Type == elf.SHT_RELA {
			if err = f.insertTLSDescriptorsForSection(descs, section); err != nil {
				return nil, err
			}
		}
	}

	return descs, nil
}

func (f *File) insertTLSDescriptorsForSection(descs map[string]libpf.Address,
	relaSection *Section) error {
	if relaSection.Link > uint32(len(f.Sections)) {
		return errors.New("rela section link is out-of-bounds")
	}
	if relaSection.Link == 0 {
		return errors.New("rela section link is empty")
	}
	if relaSection.Size > maxBytesLargeSection {
		return fmt.Errorf("relocation section too big (%d bytes)", relaSection.Size)
	}
	if relaSection.Size%uint64(unsafe.Sizeof(elf.Rela64{})) != 0 {
		return errors.New("relocation section size isn't multiple of rela64 struct")
	}

	symtabSection := &f.Sections[relaSection.Link]
	if symtabSection.Link > uint32(len(f.Sections)) {
		return errors.New("symtab link is out-of-bounds")
	}
	if symtabSection.Size%uint64(unsafe.Sizeof(elf.Sym64{})) != 0 {
		return errors.New("symbol section size isn't multiple of sym64 struct")
	}

	strtabSection := &f.Sections[symtabSection.Link]
	if strtabSection.Size > maxBytesLargeSection {
		return fmt.Errorf("string table too big (%d bytes)", strtabSection.Size)
	}

	strtabData, err := strtabSection.Data(uint(strtabSection.Size))
	if err != nil {
		return fmt.Errorf("failed to read string table: %w", err)
	}

	relaData, err := relaSection.Data(uint(relaSection.Size))
	if err != nil {
		return fmt.Errorf("failed to read relocation section: %w", err)
	}

	relaSz := int(unsafe.Sizeof(elf.Rela64{}))
	for i := 0; i < len(relaData); i += relaSz {
		rela := (*elf.Rela64)(unsafe.Pointer(&relaData[i]))

		ty := rela.Info & 0xffff
		if !(f.Machine == elf.EM_AARCH64 && elf.R_AARCH64(ty) == elf.R_AARCH64_TLSDESC) &&
			!(f.Machine == elf.EM_X86_64 && elf.R_X86_64(ty) == elf.R_X86_64_TLSDESC) {
			continue
		}

		sym := elf.Sym64{}
		symSz := int64(unsafe.Sizeof(sym))
		symNo := int64(rela.Info >> 32)
		n, err := symtabSection.ReadAt(libpf.SliceFrom(&sym), symNo*symSz)
		if err != nil || n != int(symSz) {
			return fmt.Errorf("failed to read relocation symbol: %w", err)
		}

		symStr, ok := getString(strtabData, int(sym.Name))
		if !ok {
			return errors.New("failed to get relocation name string")
		}

		descs[symStr] = libpf.Address(rela.Off)
	}

	return nil
}

// GetDebugLink reads and parses the .gnu_debuglink section.
// If the link does not exist then ErrNoDebugLink is returned.
func (f *File) GetDebugLink() (linkName string, crc int32, err error) {
	note := f.Section(".gnu_debuglink")
	if note == nil {
		return "", 0, ErrNoDebugLink
	}

	d, err := note.Data(maxBytesSmallSection)
	if err != nil {
		return "", 0, fmt.Errorf("could not read link: %w", ErrNoDebugLink)
	}
	return ParseDebugLink(d)
}

// OpenDebugLink tries to locate and open the corresponding debug ELF for this DSO.
func (f *File) OpenDebugLink(elfFilePath string, elfOpener ELFOpener) (
	debugELF *File, debugFile string) {
	f.debuglinkChecked = true
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
			debugELF.Close()
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

// Open returns a new ReadSeeker reading the ELF program body.
func (ph *Prog) Open() io.ReadSeeker {
	return io.NewSectionReader(ph, 0, 1<<63-1)
}

// Data loads the whole program header referenced data, and returns it as slice.
func (ph *Prog) Data(maxSize uint) ([]byte, error) {
	if ph.Filesz > uint64(maxSize) {
		return nil, fmt.Errorf("segment size %d is too large", ph.Filesz)
	}
	p := make([]byte, ph.Filesz)
	_, err := ph.ReadAt(p, 0)
	return p, err
}

// DataReader loads the whole program header referenced data, and returns reader to it.
func (ph *Prog) DataReader(maxSize uint) (io.Reader, error) {
	p, err := ph.Data(maxSize)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(p), nil
}

// Data loads the whole section header referenced data, and returns it as a slice.
func (sh *Section) Data(maxSize uint) ([]byte, error) {
	if sh.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, errors.New("compressed sections not supported")
	}
	if sh.FileSize > uint64(maxSize) {
		return nil, fmt.Errorf("section size %d is too large", sh.FileSize)
	}
	p := make([]byte, sh.FileSize)
	_, err := sh.ReadAt(p, 0)
	return p, err
}

// ReadAt reads bytes from given virtual address
func (f *File) ReadAt(p []byte, addr int64) (int, error) {
	return f.ReadVirtualMemory(p, addr)
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
	if _, err := f.ReadVirtualMemory(libpf.SliceFrom(&sym),
		f.symbolsAddr+int64(n)*symSz); err != nil {
		return libpf.Symbol{}, false
	}
	slen := len(name) + 1
	sname := make([]byte, slen)
	if _, err := f.ReadVirtualMemory(sname, f.stringsAddr+int64(sym.Name)); err != nil {
		return libpf.Symbol{}, false
	}

	// Verify that name matches
	if sname[slen-1] != 0 || libpf.SymbolName(sname[:slen-1]) != name {
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
			if _, err := f.ReadVirtualMemory(libpf.SliceFrom(hdr), f.gnuHash.addr); err != nil {
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
		if _, err := f.ReadVirtualMemory(libpf.SliceFrom(&bloom), offs+
			ptrSize*int64((h/ptrSizeBits)%hdr.bloomSize)); err != nil {
			return nil, err
		}
		mask := uint(1)<<(h%ptrSizeBits) |
			uint(1)<<((h>>hdr.bloomShift)%ptrSizeBits)
		if bloom&mask != mask {
			return nil, ErrSymbolNotFound
		}

		// Read the initial symbol index to start looking from
		offs += int64(hdr.bloomSize) * int64(unsafe.Sizeof(bloom))
		var i uint32
		if _, err := f.ReadVirtualMemory(libpf.SliceFrom(&i),
			offs+4*int64(h%hdr.numBuckets)); err != nil {
			return nil, err
		}
		if i == 0 {
			return nil, ErrSymbolNotFound
		}

		// Search the hash bucket
		offs += int64(4*hdr.numBuckets + 4*(i-hdr.symbolOffset))
		h |= 1
		for {
			var h2 uint32
			if _, err := f.ReadVirtualMemory(libpf.SliceFrom(&h2), offs); err != nil {
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
			if _, err := f.ReadVirtualMemory(libpf.SliceFrom(hdr), f.sysvHash.addr); err != nil {
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
		if _, err := f.ReadVirtualMemory(libpf.SliceFrom(&i), offs+4*bucket); err != nil {
			return nil, err
		}
		offs += 4 * int64(hdr.numBuckets)
		for i != 0 && i < hdr.numSymbols {
			if s, ok := f.readAndMatchSymbol(i, symbol); ok {
				return &s, nil
			}
			if _, err := f.ReadVirtualMemory(libpf.SliceFrom(&i), offs+4*int64(i)); err != nil {
				return nil, err
			}
		}
	} else {
		return nil, errors.New("symbol hash not present")
	}

	return nil, ErrSymbolNotFound
}

// LookupSymbol searches for a given symbol in the ELF
func (f *File) LookupSymbolAddress(symbol libpf.SymbolName) (libpf.SymbolValue, error) {
	s, err := f.LookupSymbol(symbol)
	if err != nil {
		return libpf.SymbolValueInvalid, err
	}
	return s.Address, nil
}

// loadSymbolTable reads given symbol table
func (f *File) loadSymbolTable(name string) (*libpf.SymbolMap, error) {
	symTab := f.Section(name)
	if symTab == nil {
		return nil, fmt.Errorf("failed to read %v: section not present", name)
	}
	if symTab.Link >= uint32(len(f.Sections)) {
		return nil, fmt.Errorf("failed to read %v strtab: link %v out of range",
			name, symTab.Link)
	}
	strTab := f.Sections[symTab.Link]
	strs, err := strTab.Data(maxBytesLargeSection)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v: %v", strTab.Name, err)
	}
	syms, err := symTab.Data(maxBytesLargeSection)
	if err != nil {
		return nil, fmt.Errorf("failed to read %v: %v", name, err)
	}

	symMap := libpf.SymbolMap{}
	symSz := int(unsafe.Sizeof(elf.Sym64{}))
	for i := 0; i < len(syms); i += symSz {
		sym := (*elf.Sym64)(unsafe.Pointer(&syms[i]))
		name, ok := getString(strs, int(sym.Name))
		if !ok {
			continue
		}
		symMap.Add(libpf.Symbol{
			Name:    libpf.SymbolName(name),
			Address: libpf.SymbolValue(sym.Value),
			Size:    sym.Size,
		})
	}
	symMap.Finalize()

	return &symMap, nil
}

// ReadSymbols reads the full dynamic symbol table from the ELF
func (f *File) ReadSymbols() (*libpf.SymbolMap, error) {
	return f.loadSymbolTable(".symtab")
}

// ReadDynamicSymbols reads the full dynamic symbol table from the ELF
func (f *File) ReadDynamicSymbols() (*libpf.SymbolMap, error) {
	return f.loadSymbolTable(".dynsym")
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
	return f.Section(".go.buildinfo") != nil || f.Section(".gopclntab") != nil
}
