// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// This implements Go 1.2+ .pclntab symbol parsing as defined
// in http://golang.org/s/go12symtab. The Golang runtime implementation of
// this is in go/src/runtime/symtab.go, but unfortunately it is not exported.

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"go/version"
	"io"
	"sort"
	"strings"
	"unsafe"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	// internally used gopclntab version
	goInvalid = 0
	go1_2     = 2
	go1_16    = 16
	go1_18    = 18
	go1_20    = 20

	// Offset of the text field in moduledata struct for Go 1.16+
	// https://github.com/golang/go/blob/release-branch.go1.16/src/runtime/symtab.go#L370
	textOffset = 22 * 8
	// section name for the module data for Go 1.26+
	moduleDataSectionName = ".go.module"

	// sparseIndexStep is the interval of the function lookup map entries stored
	// in the in-memory sparse index.
	sparseIndexStep = 1024

	// funcDataCacheSize is the maximum number of cached function data entries.
	funcDataCacheSize = 1024
)

func goMagicToVersion(magic uint32) uint8 {
	// pclntab header magic bytes identifying Go version
	switch magic {
	case 0xfffffffb: // Go 1.2
		return go1_2
	case 0xfffffffa: // Go 1.16
		return go1_16
	case 0xfffffff0: // Go 1.18
		return go1_18
	case 0xfffffff1: // Go 1.20
		return go1_20
	default:
		return goInvalid
	}
}

// pclntabHeader is the Golang pclntab header structure for Go 1.16 and newer
// structural definition of this is found in go/src/runtime/symtab.go as pcHeader
type pclntabHeader struct {
	// magic is one of the magicGo1_xx constants identifying the version
	magic uint32
	// pad is unused and is needed for alignment
	pad uint16
	// quantum is the CPU instruction size alignment (e.g. 1 for x86, 4 for arm)
	quantum uint8
	// ptrSize is the CPU pointer size in bytes
	ptrSize uint8
	// numFuncs is the number of function definitions to follow
	numFuncs uint64
	// nfiles is the number of files
	nfiles uint
}

// pclntabHeaderOffset is the second part of pclntab header with section offsets.
// structural definition of this is found in go/src/runtime/symtab.go as pcHeader
type pclntabHeaderOffsets struct {
	funcnameOffset uintptr
	cuOffset       uintptr
	filetabOffset  uintptr
	pctabOffset    uintptr
	pclnOffset     uintptr
}

// pclntabHeaderSize is the minimum size of valid gopclntab that includes all headers.
const pclntabHeaderSize = int(unsafe.Sizeof(pclntabHeader{}) + unsafe.Sizeof(pclntabHeaderOffsets{}) + unsafe.Sizeof([1]uintptr{}))

// pclntabFunc is the common portion of the Golang function definition.
type pclntabFunc struct {
	// The actual data is preceded with the function start PC value, which is
	// a pointer (pre-Go1.18) or fixed 32-bit offset from .text start (Go1.18+).
	// startPc                   uintptr | uint32
	nameOff, argsSize, frameSize int32
	pcspOff, pcfileOff, pclnOff  int32
	nfuncData, npcData           int32
}

// pcvalDecoder is a decoder for pcval tables. A pcval table decodes to
// a Program Counter (pc) and a value (val) associated with it. The meaning of
// the value depends on which table is being processed: the Stack Delta in
// bytes, the source filename index, or the source line number.
type pcvalDecoder struct {
	rdr      libpf.ViewAtReader
	buf      []byte
	start    int64
	end      int64
	cur      int64
	pc       uint
	val      int32
	minValid int32
	quantum  uint8
}

// pclntabHeaderSignature returns a byte slice that can be
// used to verify if some bytes represent a valid pclntab header.
func pclntabHeaderSignature(arch elf.Machine) []byte {
	var quantum byte

	switch arch {
	case elf.EM_X86_64:
		quantum = 0x1
	case elf.EM_AARCH64:
		quantum = 0x4
	}

	//  - the first byte is ignored and not included in this signature
	//    as it is different per Go version (see magicGo1_XX)
	//  - next three bytes are 0xff (shared on magicGo1_XX)
	//  - pad is zero (two bytes)
	//  - quantum depends on the architecture
	//  - ptrSize is 8 for 64 bit systems (arm64 and amd64)

	return []byte{0xff, 0xff, 0xff, 0x00, 0x00, quantum, 0x08}
}

// newPcval returns a pcval decoder that reads the tables via the given
// reader. Call reset() to position the decoder at the start of a table, and
// to set the minimum valid decoded value for the table type.
func newPcvalDecoder(rdr libpf.ViewAtReader, start, end int64, quantum uint8) pcvalDecoder {
	p := pcvalDecoder{
		rdr:     rdr,
		start:   start,
		end:     end,
		val:     -1,
		quantum: quantum,
	}
	return p
}

func (p *pcvalDecoder) reset(offset, minValid int32) {
	p.cur = p.start + int64(offset)
	p.buf = nil
	p.pc = 0
	p.val = -1
	p.minValid = minValid
}

func (p *pcvalDecoder) getFirst(offset int32) (int32, error) {
	p.reset(offset, 0)
	_, val, err := p.step()
	if err == io.EOF {
		// The Go linker reserves a zero byte at pctab[0] so that a function
		// without pcval data refers to it by offset zero. A non-zero offset
		// that yields no entry means the pclntab is malformed.
		return 0, fmt.Errorf("pcval table at offset %d has no valid first entry", offset)
	}
	if err != nil {
		return 0, err
	}
	return val, nil
}

func (p *pcvalDecoder) mapValue(offset int32, pcDiff uint) (int32, error) {
	p.reset(offset, 0)
	for {
		_, val, err := p.step()
		if err != nil {
			return 0, err
		}
		if pcDiff < p.pc {
			return val, nil
		}
	}
}

func (p *pcvalDecoder) fill() error {
	if p.cur >= p.end {
		return io.EOF
	}
	buf, err := p.rdr.ViewAt(int64(p.cur), 1)
	if len(buf) == 0 {
		return err
	}
	n := min(p.end-p.cur, int64(len(buf)))
	p.cur += n
	p.buf = buf[:n]
	return nil
}

// getInt reads one zig-zag encoded integer. It returns an error if the data
// ends in the middle of the encoding: a truncated value is otherwise
// indistinguishable from a real zero, which would let a malformed table
// decode as a valid entry.
func (p *pcvalDecoder) getInt() (uint32, error) {
	var v, shift uint32
	for {
		if len(p.buf) == 0 {
			if err := p.fill(); err != nil {
				return 0, err
			}
		}
		b := p.buf[0]
		p.buf = p.buf[1:]
		v |= (uint32(b) & 0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return v, nil
}

// step executes one line of the pcval table, and returns the PC where the
// new value starts along with the new value. It returns io.EOF on the
// end-of-table marker; any other error marks the table as corrupt (truncated
// data, or a value below the minimum valid for the table type).
func (p *pcvalDecoder) step() (uint, int32, error) {
	d, err := p.getInt()
	if err != nil {
		return 0, 0, err
	}
	if d == 0 {
		return 0, 0, io.EOF
	}
	pc := p.pc
	if d&1 != 0 {
		d = ^(d >> 1)
	} else {
		d >>= 1
	}
	// Both values are decoded before either is applied, so that a truncated
	// entry leaves val and pcEnd untouched rather than half updated.
	pcDelta, err := p.getInt()
	if err != nil {
		return 0, 0, err
	}
	p.val += int32(d)
	p.pc += uint(pcDelta) * uint(p.quantum)
	if p.val < p.minValid {
		return 0, 0, fmt.Errorf("pcval near %d: %d is below %d",
			p.cur-int64(len(p.buf)), p.val, p.minValid)
	}
	return pc, p.val, nil
}

// searchGoPclntab uses heuristic to find the gopclntab from RO data. Final fallback path
// when sections and symbol table are not present.
func searchGoPclntab(ef *pfelf.File) (start, end libpf.SymbolValue) {
	signature := pclntabHeaderSignature(ef.Machine)
	sigEnd := 1 + len(signature)

	rdr := pfbufio.Reader{}
	defer rdr.Release()

	for i := range ef.Progs {
		p := &ef.Progs[i]
		// Search for the .rodata (read-only) and .data.rel.ro (read-write which gets
		// turned into read-only after relocations handling via GNU_RELRO header).
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == elf.PF_X || p.Flags&elf.PF_R != elf.PF_R {
			continue
		}

		// Skip segments that are too small anyway.
		if p.Filesz < uint64(pclntabHeaderSize) {
			continue
		}

		rdr.InitFromView(ef.Underlying(), int64(p.Off), int64(p.Filesz))

		for {
			data, err := rdr.Peek(pclntabHeaderSize)
			if err != nil {
				break
			}
			if bytes.Equal(data[1:sigEnd], signature) {
				// Check the 'magic' against supported list, and if valid, use this
				// location as the .gopclntab base. Otherwise, continue just search
				// for next candidate location.
				hdr := (*pclntabHeader)(unsafe.Pointer(&data[0]))
				if goMagicToVersion(hdr.magic) != goInvalid {
					// No way to know the real size, allow up to end of segment.
					vaddr := libpf.SymbolValue(p.Vaddr)
					return vaddr + libpf.SymbolValue(rdr.Tell()), vaddr + libpf.SymbolValue(p.Filesz)
				}
			}
			rdr.Discard(8)
		}
	}

	return 0, 0
}

// locateGoPclntab determine the location of .gopclntab data from a given pfelf.File.
func locateGoPclntab(ef *pfelf.File) (fileoff, size int64, err error) {
	if s := ef.Section(".gopclntab"); s != nil {
		// Load the .gopclntab via section if available.
		return int64(s.Offset), int64(s.Size), nil
	}

	// Try the runtime.pclntab symbols, as the .gopclntab section is not available
	// on PIE binaries. A full symbol table read is needed as these are not dynamic symbols.
	// Consequently these symbols might be unavailable on a stripped binary.
	var start, end libpf.SymbolValue
	ef.VisitSymbols(func(sym libpf.Symbol) bool {
		switch sym.Name {
		case "runtime.pclntab":
			start = sym.Address
		case "runtime.epclntab":
			end = sym.Address
		}
		return start == 0 || end == 0
	})
	if start == 0 || end == 0 {
		// It seems the Go binary was stripped. So we use the heuristic approach.
		start, end = searchGoPclntab(ef)
		if start == 0 {
			return 0, 0, errors.New("failed to search gopclntab")
		}
	} else if start >= end {
		return 0, 0, fmt.Errorf("invalid .gopclntab symbols: %v-%v", start, end)
	}

	p := ef.ProgByVirtualAddress(uint64(start))
	if p == nil {
		return 0, 0, errors.New(".gopclntab virtual address is unmappable")
	}
	return int64(p.Off) + int64(start) - int64(p.Vaddr), int64(end - start), nil
}

// Gopclntab is the API for extracting data from .gopclntab
type Gopclntab struct {
	// dataRef holds a reference on the backing pfelf.File, keeping the
	// underlying reader open (and readable) past the File's Close. It is
	// released on Close.
	dataRef  io.Closer
	readerAt libpf.ViewAtReader

	// funcDataCache is an LRU cache mapping the function descriptor offset
	// to the symbolization data of a function.
	funcDataCache *lru.LRU[uintptr, *functionData]

	// pcval decodes the pcval tables (source files and line numbers) of the
	// cached functions directly from the file via the reader. Symbolize is
	// not safe for concurrent use, so a single decoder is enough.
	pcval pcvalDecoder

	pclntabOffset int64
	pclntabSize   int64

	textStart uint64
	textEnd   uint64

	numFuncs int
	numFiles uint

	version     uint8
	quantum     uint8
	ptrSize     uint8
	funSize     uint8
	pcSize      uint8
	funcMapSize uint8

	funcnameOffset int64
	cuOffset       int64
	filetabOffset  int64
	pctabOffset    int64
	pclnOffset     int64

	// sparseIndex holds the entry pc (relative to the text start) of every
	// sparseIndexStep-th entry of the function lookup map, including the
	// sentinel entry marking the end of the Go code. It allows bounding the
	// file search for a function to a small window of the function lookup
	// map. The pcs are stored as int32 so that pcs below the text start
	// compare negative.
	sparseIndex []int32
	// initFailed records that the symbolization initialization was attempted
	// and failed (e.g. corrupt function lookup map): it is not retried for
	// every symbolization call.
	initFailed bool
}

func (g *Gopclntab) walkFuncMap(visitor func(pc, endPc uint64, fun *pclntabFunc) error) (start, end uint64, err error) {
	// mapRdr reads the function lookup map entries sequentially.
	mapRdr := pfbufio.Reader{}
	mapRdr.InitSlideView(g.readerAt, g.pclntabOffset+g.pclnOffset, int64(g.numFuncs+1)*int64(g.funcMapSize))
	defer mapRdr.Release()

	// descRdr reads the function descriptors. They are expected to be in (near) sequential order,
	// which is currently true for Golang generated binaries.
	descRdr := pfbufio.Reader{}
	descRdr.InitSlideView(g.readerAt, g.pclntabOffset+g.pclnOffset, g.pclntabSize-g.pclnOffset)
	defer descRdr.Release()

	var readOffset func() uint64
	var decodeFuncPc func(data []byte) uint64

	textStart := g.textStart
	if g.version >= go1_18 {
		// 32-bit offsets
		readOffset = func() uint64 { return uint64(mapRdr.Uint32()) }
		decodeFuncPc = func(data []byte) uint64 {
			return textStart + uint64(binary.LittleEndian.Uint32(data))
		}
	} else {
		// pointer type
		readOffset = mapRdr.Uint64
		decodeFuncPc = binary.LittleEndian.Uint64
	}

	startPc := readOffset() + textStart
	pc := startPc
	for i := 0; i < g.numFuncs; i++ {
		funcOff := readOffset()
		// Seek to, and read the function descriptor: its entry PC, and the
		// pclntabFunc structure.
		if _, err := descRdr.Seek(int64(funcOff), io.SeekStart); err != nil {
			return 0, 0, fmt.Errorf("func %v descriptor is invalid: %v", i, err)
		}
		data, err := descRdr.ReadN(int(g.pcSize) + int(unsafe.Sizeof(pclntabFunc{})))
		if err != nil {
			return 0, 0, fmt.Errorf("func %v descriptor is invalid: %v", i, err)
		}
		funcPc := decodeFuncPc(data)
		fun := (*pclntabFunc)(unsafe.Pointer(&data[g.pcSize]))
		if pc != funcPc {
			return 0, 0, fmt.Errorf("func %v descriptor is invalid (pc %x/%x)",
				i, pc, funcPc)
		}
		endPc := readOffset() + textStart
		if err := visitor(pc, endPc, fun); err != nil {
			return 0, 0, err
		}
		pc = endPc
	}
	return startPc, pc, nil
}

// LookupSymbols searches for the given symbols in .gopclntab, and fills in
// the Address and Size fields of each symbol found in it. The caller can
// determine if a symbol was resolved by checking if its Address is set.
func (g *Gopclntab) LookupSymbols(symbols []libpf.Symbol) error {
	// Index the still unresolved symbols by name.
	pending := make(map[libpf.SymbolName]int, len(symbols))
	for idx, symbol := range symbols {
		if symbol.Address == 0 && symbol.Size == 0 {
			pending[symbol.Name] = idx
		}
	}
	if len(pending) == 0 {
		return nil
	}

	// First, find the funcnametab offset of each unresolved symbol name.
	offsets := make(map[int32]int, len(pending))
	rdr := pfbufio.Reader{}
	rdr.InitSlideView(g.readerAt, g.pclntabOffset+g.funcnameOffset, g.cuOffset-g.funcnameOffset)
	err := rdr.WalkAllStrings(func(offs int64, funcName string) error {
		if idx, ok := pending[libpf.SymbolName(funcName)]; ok {
			delete(pending, libpf.SymbolName(funcName))
			offsets[int32(offs)] = idx
			if len(pending) == 0 {
				return io.EOF
			}
		}
		return nil
	})
	rdr.Release()
	if err != nil {
		return err
	}

	// Then, walk the function map to resolve each recorded offset into a symbol.
	_, _, err = g.walkFuncMap(func(pc, endPc uint64, fun *pclntabFunc) error {
		if idx, ok := offsets[fun.nameOff]; ok {
			symbols[idx].Address = libpf.SymbolValue(pc)
			symbols[idx].Size = uint64(endPc - pc)
			delete(offsets, fun.nameOff)
			if len(offsets) == 0 {
				return io.EOF
			}
		}
		return nil
	})
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}

// NewGopclntab parses and returns the parsed data for further operations.
// It takes a reference on the backing pfelf.File, keeping the underlying
// reader open (and readable) even after the File has been closed. This
// reference is released on Gopclntab.Close.
func NewGopclntab(ef *pfelf.File) (g *Gopclntab, err error) {
	pclntabOffset, pclntabSize, err := locateGoPclntab(ef)
	if err != nil {
		return nil, err
	}

	if pclntabSize < int64(pclntabHeaderSize) {
		return nil, fmt.Errorf(".gopclntab is too short (%v)", pclntabSize)
	}

	headerData := make([]byte, pclntabHeaderSize)
	if _, err := ef.Underlying().ReadAt(headerData, pclntabOffset); err != nil {
		return nil, err
	}

	hdr := (*pclntabHeader)(unsafe.Pointer(&headerData[0]))
	pos := unsafe.Sizeof(pclntabHeader{})
	g = &Gopclntab{
		readerAt:      ef.Underlying(),
		pclntabOffset: pclntabOffset,
		pclntabSize:   pclntabSize,
		version:       goMagicToVersion(hdr.magic),
		quantum:       hdr.quantum,
		ptrSize:       hdr.ptrSize,
		funSize:       hdr.ptrSize + uint8(unsafe.Sizeof(pclntabFunc{})),
		funcMapSize:   hdr.ptrSize * 2,
		numFuncs:      int(hdr.numFuncs),
		numFiles:      hdr.nfiles,
	}
	if hdr.pad != 0 || hdr.ptrSize != 8 {
		g.version = goInvalid
	}

	switch g.version {
	case go1_16:
		g.pcSize = 8
	case go1_18, go1_20:
		g.pcSize = 4
		g.textStart = uint64(*(*uintptr)(unsafe.Pointer(&headerData[pos])))
		pos += uintptr(hdr.ptrSize)

		if g.textStart == 0 {
			// Starting from Go 1.26, textStart address in pclntab is always set to 0.
			// Therefore we need to get it from either `runtime.text` symbol or moduledata.
			// Note that it does not always match the address of `.text` section
			// (for example with cgo binaries or when built with -linkmode=external).
			g.textStart, err = findTextStart(ef)
			if err != nil {
				return nil, fmt.Errorf("failed to find text start: %w", err)
			}
		}
		// With the change of the type of the first field of _func in Go 1.18, this
		// value is now hard coded.
		//
		//nolint:lll
		// See https://github.com/golang/go/blob/6df0957060b1315db4fd6a359eefc3ee92fcc198/src/debug/gosym/pclntab.go#L376-L382
		g.funcMapSize = 2 * 4
		g.funSize = 4 + uint8(unsafe.Sizeof(pclntabFunc{}))
	default:
		return nil, fmt.Errorf("unsupported header: %x, %x, %x", hdr.magic, hdr.pad, hdr.ptrSize)
	}

	hdro := (*pclntabHeaderOffsets)(unsafe.Pointer(&headerData[pos]))
	g.funcnameOffset = int64(hdro.funcnameOffset)
	g.cuOffset = int64(hdro.cuOffset)
	g.filetabOffset = int64(hdro.filetabOffset)
	g.pctabOffset = int64(hdro.pctabOffset)
	g.pclnOffset = int64(hdro.pclnOffset)

	if g.funcnameOffset >= g.cuOffset ||
		g.cuOffset >= g.filetabOffset ||
		g.filetabOffset >= g.pctabOffset ||
		g.pctabOffset >= g.pclnOffset ||
		g.pclnOffset >= pclntabSize ||
		uint64(g.numFuncs)+1 > uint64(pclntabSize-g.pclnOffset)/uint64(g.funcMapSize) {
		return nil, fmt.Errorf("corrupt header (%x < %x < %x < %x < %x)",
			g.funcnameOffset, g.cuOffset, g.filetabOffset, g.pctabOffset, g.pclnOffset)
	}

	g.pcval = newPcvalDecoder(g.readerAt, g.pclntabOffset+g.pctabOffset, g.pclntabOffset+g.pclnOffset, g.quantum)

	// Take the reference only once the pclntab is known to be usable: on the
	// error paths above there is no Gopclntab to release it on Close.
	g.dataRef = ef.Take()
	return g, nil
}

// Close releases the resources held for symbolization.
func (g *Gopclntab) Close() error {
	if g.dataRef != nil {
		_ = g.dataRef.Close()
		g.readerAt = nil
		g.dataRef = nil
	}
	if g.funcDataCache != nil {
		g.funcDataCache.Purge()
		g.funcDataCache = nil
	}
	g.sparseIndex = nil
	g.initFailed = false
	return nil
}

// functionData caches the data needed for symbolization of one function:
// the resolved function name from the function descriptor, and the offsets
// of the associated pcval tables for source files and line numbers.
type functionData struct {
	startPc uint64
	// npcData is the number of pc data entries of the function, needed to
	// resolve the source file names from the cutab area.
	npcData  int32
	funcName libpf.String
	// pcfileOff and pclnOff are the offsets of the pcval tables within the
	// pctab area. Zero means the function has no such table.
	pcfileOff int32
	pclnOff   int32
}

// hashFuncOff hashes a function descriptor offset for the LRU cache.
func hashFuncOff(v uintptr) uint32 {
	return uint32(hash.Uint64(uint64(v)))
}

// initSymbolization builds the in-memory sparse index of the function lookup
// map, and allocates the read caches. It is called on the first symbolization
// so that binaries that are only used for stack delta generation do not pay
// for it.
func (g *Gopclntab) initSymbolization() error {
	sparse := make([]int32, 0, g.numFuncs/sparseIndexStep+2)
	idx := int32(0)
	_, end, err := g.walkFuncMap(func(pc, _ uint64, _ *pclntabFunc) error {
		// Store the entry pc of every sparseIndexStep-th entry in the
		// sparse index. The pcs are stored relative to the text start.
		if idx%int32(sparseIndexStep) == 0 {
			sparse = append(sparse, int32(pc-uint64(g.textStart)))
		}
		idx++
		return nil
	})
	if err != nil {
		return err
	}
	g.textEnd = end

	// The function lookup map has one extra sentinel entry at the end to
	// indicate the end of Go code. It holds the end pc of the last function.
	// Record it to bound the last window.
	sparse = append(sparse, int32(end-uint64(g.textStart)))

	funcDataCache, err := lru.New[uintptr, *functionData](funcDataCacheSize, hashFuncOff)
	if err != nil {
		return err
	}
	g.funcDataCache = funcDataCache
	g.sparseIndex = sparse
	return nil
}

// readFuncMapEntry reads the function lookup map entry at the given index
// from the file. It returns (0, 0) if the entry cannot be read.
func (g *Gopclntab) readFuncMapEntry(index int) (pc uint64, funcOff uintptr) {
	var buf [16]byte
	off := g.pclntabOffset + g.pclnOffset + int64(index)*int64(g.funcMapSize)
	n, err := g.readerAt.ReadAt(buf[:g.funcMapSize], off)
	if err != nil || n != int(g.funcMapSize) {
		return 0, 0
	}
	if g.version >= go1_18 {
		return uint64(g.textStart) + uint64(binary.LittleEndian.Uint32(buf[0:4])),
			uintptr(binary.LittleEndian.Uint32(buf[4:8]))
	}
	return binary.LittleEndian.Uint64(buf[0:8]), uintptr(binary.LittleEndian.Uint64(buf[8:16]))
}

// searchFuncMapWindow returns the index of the last function lookup map entry
// whose pc is less than or equal to the given pc, searching the window that
// is delimited by the neighboring sparse index entries. The caller guarantees
// that the sparse index entry pc is less than or equal to the given pc.
func (g *Gopclntab) searchFuncMapWindow(sparseIdx int, pc uint64) int {
	// The sparse index records every sparseIndexStep-th entry, so the window
	// of the function lookup map is derived from the position of the sparse
	// index entry. The sentinel window is clamped to the number of functions.
	lo := min(sparseIdx*sparseIndexStep, g.numFuncs)
	hi := min(lo+sparseIndexStep, g.numFuncs+1)
	// The search lambda makes 'sort.Search' return the first entry in the
	// window that is larger than the pc. Thus -1 is needed to get the index
	// of the entry which is equal or less than the pc.
	return lo + sort.Search(hi-lo, func(i int) bool {
		midPc, _ := g.readFuncMapEntry(lo + i)
		return midPc > pc
	}) - 1
}

// readFuncName reads the function name at the given offset in the function
// name table area.
func (g *Gopclntab) readFuncName(nameOff int32) libpf.String {
	if nameOff < 0 || int64(nameOff) >= g.cuOffset-g.funcnameOffset {
		return libpf.NullString
	}
	str, _ := libpf.InternFromView(g.readerAt, g.pclntabOffset+g.funcnameOffset+int64(nameOff), g.pclntabOffset+g.cuOffset)
	return str
}

// readFiletabName resolves the source file name for the given file index in
// the cutab area, and reads the string at the resulting offset in the file
// name table area. npcData is the number of pc data entries of the function.
func (g *Gopclntab) readFiletabName(fileIndex, npcData int32) libpf.String {
	cuIndex := int64(fileIndex) + int64(npcData)
	if cuIndex < 0 || 4*cuIndex+4 > g.filetabOffset-g.cuOffset {
		return libpf.NullString
	}
	var buf [4]byte
	n, err := g.readerAt.ReadAt(buf[:], g.pclntabOffset+g.cuOffset+4*cuIndex)
	if err != nil || n != 4 {
		return libpf.NullString
	}
	fileOff := int64(int32(binary.LittleEndian.Uint32(buf[:])))
	if fileOff < 0 || fileOff >= g.pctabOffset-g.filetabOffset {
		return libpf.NullString
	}
	str, _ := libpf.InternFromView(g.readerAt, g.pclntabOffset+g.filetabOffset+fileOff, g.pclntabOffset+g.pctabOffset)
	return str
}

// readFuncData reads the function descriptor at the given offset in the
// functab area from the file, and caches the data needed for symbolization.
// It returns nil if the descriptor is invalid.
func (g *Gopclntab) readFuncData(funcOff uintptr) *functionData {
	// Get the function data. Compare without overflowing, making sure
	// funcOff+funSize does not wrap around.
	areaSize := uint64(g.pclntabSize - g.pclnOffset)
	if uint64(funcOff) > areaSize || uint64(funcOff)+uint64(g.funSize) > areaSize {
		return nil
	}
	var buf [8 + unsafe.Sizeof(pclntabFunc{})]byte
	n, err := g.readerAt.ReadAt(buf[:g.funSize], g.pclntabOffset+g.pclnOffset+int64(funcOff))
	if err != nil || n != int(g.funSize) {
		return nil
	}
	fun := (*pclntabFunc)(unsafe.Pointer(&buf[g.pcSize]))
	fd := &functionData{npcData: fun.npcData}
	if g.version >= go1_18 {
		fd.startPc = uint64(g.textStart) + uint64(binary.LittleEndian.Uint32(buf[0:4]))
	} else {
		fd.startPc = binary.LittleEndian.Uint64(buf[0:8])
	}
	fd.funcName = g.readFuncName(fun.nameOff)
	fd.pcfileOff = fun.pcfileOff
	fd.pclnOff = fun.pclnOff
	return fd
}

// getCachedFuncData returns the symbolization data for the function
// descriptor at the given offset, reading it from the file on a cache miss.
func (g *Gopclntab) getCachedFuncData(funcOff uintptr) *functionData {
	if fd, ok := g.funcDataCache.Get(funcOff); ok {
		return fd
	}
	fd := g.readFuncData(funcOff)
	if fd == nil {
		return nil
	}
	g.funcDataCache.Add(funcOff, fd)
	return fd
}

// Symbolize returns the file, line and function information for given PC
func (g *Gopclntab) Symbolize(pc uint64) (sourceFile libpf.String, line uint, funcName libpf.String) {
	if g.sparseIndex == nil {
		if g.readerAt == nil || g.initFailed {
			return libpf.NullString, 0, libpf.NullString
		}
		if g.initSymbolization() != nil {
			// Initialization failed (e.g. corrupt function lookup map): do
			// not retry the full map walk for every symbolization call.
			g.initFailed = true
			return libpf.NullString, 0, libpf.NullString
		}
	}

	// Fast check for if within gopclntab code range
	if pc < g.textStart || pc >= g.textEnd {
		return libpf.NullString, 0, libpf.NullString
	}

	// Binary search the sparse index for the window of the function lookup
	// map that can contain the entry matching the pc. The search lambda
	// makes 'sort.Search' return the first sparse index entry that is larger
	// than the pc. Thus -1 is needed to get the entry which is equal or less
	// than the pc. The sparse index stores the pc values relative to the
	// text start, as int32: pcs below the text start compare negative, and
	// find no matching window.
	pcRel := int32(uint64(pc) - uint64(g.textStart))
	idx := sort.Search(len(g.sparseIndex), func(i int) bool {
		return g.sparseIndex[i] > pcRel
	}) - 1
	if idx < 0 {
		return libpf.NullString, 0, libpf.NullString
	}

	// Then search the function lookup map entries in the window by reading
	// them from the file via the cached reader.
	funcIdx := g.searchFuncMapWindow(idx, uint64(pc))
	if funcIdx >= g.numFuncs {
		// The pc is higher than any Go function address.
		return libpf.NullString, 0, libpf.NullString
	}

	mapPc, funcOff := g.readFuncMapEntry(funcIdx)
	if mapPc == 0 {
		return libpf.NullString, 0, libpf.NullString
	}
	fd := g.getCachedFuncData(funcOff)
	if fd == nil || fd.startPc != mapPc {
		return libpf.NullString, 0, libpf.NullString
	}
	pcDiff := uint(uint64(pc) - mapPc)

	funcName = fd.funcName
	if fd.pcfileOff != 0 {
		// Resolve the source file name from the pcfile table.
		if fileIndex, err := g.pcval.mapValue(fd.pcfileOff, pcDiff); err == nil {
			sourceFile = g.readFiletabName(fileIndex, fd.npcData)
		}
	}
	if fd.pclnOff != 0 {
		// Read the line number from the pcln table.
		if lineNo, err := g.pcval.mapValue(fd.pclnOff, pcDiff); err == nil {
			line = uint(lineNo)
		}
	}
	return sourceFile, line, funcName
}

func findTextStart(ef *pfelf.File) (uint64, error) {
	// Get textstart from moduledata
	// Starting from Go 1.26, moduledata has its own `.go.module` section.
	// Since this function is expected to be called only for Go 1.26+ binaries,
	// we can expect that the section exists and error out if it does not.
	moduleDataSection := ef.Section(moduleDataSectionName)
	if moduleDataSection == nil || moduleDataSection.Type == elf.SHT_NOBITS {
		return 0, errors.New("could not find .go.module section or it is empty")
	}

	var textBytes [8]byte
	_, err := moduleDataSection.ReadAt(textBytes[:], textOffset)
	if err != nil {
		return 0, fmt.Errorf("could not read .go.module section at offset %v: %w", textOffset, err)
	}

	return binary.LittleEndian.Uint64(textBytes[:]), nil
}

type strategy uint8

const (
	strategyUnknown strategy = iota
	strategyFramePointer
	strategyDeltasWithFrame
	strategyDeltasWithoutFrame
)

// noFPSourceSuffixes lists the go runtime source files that call assembly code
// which trashes RBP. These source files need to use explicit SP delta so that
// RBP can be recovered, and be then further used for frame pointer based unwinding.
// This lists the most notable problem cases from Go runtime.
// TODO(tteras) Go Runtime files calling internal.bytealg.Index* may need to be added here.
var noFPSourceSuffixes = []string{
	"/src/crypto/sha1/sha1.go",
	"/src/crypto/sha256/sha256.go",
	"/src/crypto/sha512/sha512.go",
	"/src/crypto/elliptic/p256_asm.go",
	"/src/internal/cpu/cpu_arm64.go",
	"/src/internal/cpu/cpu_x86.go",
	"golang.org/x/crypto/curve25519/curve25519_amd64.go",
	"golang.org/x/crypto/chacha20poly1305/chacha20poly1305_amd64.go",
}

// getSourceFileStrategyX86 categorizes sourceFile's unwinding strategy based on its name for amd64
// strategyUnknown is returned if normal strategy resolution should be used.
func getSourceFileStrategyX86(sourceFile string) strategy {
	// Most of the assembly code needs explicit SP delta as they do not
	// create stack frame. Do not recover RBP as it is not modified.
	if strings.HasSuffix(sourceFile, ".s") {
		return strategyDeltasWithoutFrame
	}
	// Check for the Go source files needing SP delta unwinding to recover RBP
	for _, suffix := range noFPSourceSuffixes {
		if strings.HasSuffix(sourceFile, suffix) {
			return strategyDeltasWithFrame
		}
	}
	return strategyUnknown
}

// getFunctionDelta determines the special unwind opcode if needed
func getFunctionUnwindInfo(sourceFile string, arch elf.Machine, useFP bool) *sdtypes.UnwindInfo {
	unwindInfoFramePointerOrStop := &sdtypes.UnwindInfoStop
	unwindInfoGoAsmcgocallOrStop := &sdtypes.UnwindInfoStop
	unwindInfoGoMorestackOrStop := &sdtypes.UnwindInfoStop
	if useFP {
		unwindInfoFramePointerOrStop = &sdtypes.UnwindInfoFramePointer
		unwindInfoGoAsmcgocallOrStop = &sdtypes.UnwindInfoGoAsmcgocall
		unwindInfoGoMorestackOrStop = &sdtypes.UnwindInfoGoMorestack
	}

	switch sourceFile {
	case "runtime.goexit", "runtime.mstart":
		// goexit - return address in all goroutine stacks
		// mstart - topmost for the go runtime main stacks
		return &sdtypes.UnwindInfoStop
	case "runtime.mcall": // unsupported at this time
		return &sdtypes.UnwindInfoStop
	case "runtime.asmcgocall":
		if arch == elf.EM_AARCH64 {
			// On arm64 r29 is overwritten with g0's frame pointer, so the FP chain
			// is broken across the stack switch. Recover the user goroutine's saved
			// context and continue FP unwinding there.
			return unwindInfoGoAsmcgocallOrStop
		}
		// asmcgocall FP is valid only on x86-64
		return unwindInfoFramePointerOrStop
	case "runtime.morestack":
		// morestack clears the frame pointer before calling newstack, but first
		// saves the caller's sp/pc/bp into the goroutine's gobuf, so the caller
		// frame is recovered from there.
		// Note that runtime.morestack_noctxt is deliberately not handled: it only
		// clears the context register and jumps to morestack, so at that point
		// nothing has been saved yet.
		return unwindInfoGoMorestackOrStop
	case "runtime.systemstack", "runtime.nanotime1", "time.now", "runtime.walltime":
		// functions which preserve the frame pointer chain across the g0/user stack boundary
		// so that the standard FP unwinding traverses it naturally.
		return unwindInfoFramePointerOrStop
	case "runtime.sigreturn", "runtime.sigreturn__sigaction":
		// signal frame restorers
		return &sdtypes.UnwindInfoSignal
	}
	return nil
}

// parseX86pcspFunc extracts interval information from x86_64 based sp offsets.
func parseX86pcspFunc(bb *sdtypes.BasicBlock, p *pcvalDecoder, s strategy) error {
	for {
		pc, val, err := p.step()
		if err != nil {
			return err
		}
		info := sdtypes.UnwindInfo{
			BaseReg: support.UnwindRegSp,
			Param:   val + 8,
		}
		if s == strategyDeltasWithFrame && info.Param >= 16 {
			info.AuxBaseReg = support.UnwindRegCfa
			info.AuxParam = -16
		}
		bb.Deltas.Add(uint32(pc), info)
	}
}

// parseArm64pcspFunc extracts interval information from ARM64 based sp offsets.
func parseArm64pcspFunc(bb *sdtypes.BasicBlock, p *pcvalDecoder, s strategy) error {
	for {
		pc, val, err := p.step()
		if err != nil {
			return err
		}
		var info sdtypes.UnwindInfo
		if val == 0 {
			// Return instruction, function prologue or leaf function body: unwind via LR.
			info = sdtypes.UnwindInfoLR
		} else {
			// Regular basic block in the function body: unwind via SP.
			info = sdtypes.UnwindInfo{
				// Unwind via SP offset.
				BaseReg: support.UnwindRegSp,
				Param:   val,
			}
			if s == strategyDeltasWithFrame {
				// On ARM64, the previous LR value is stored to top-of-stack.
				info.AuxBaseReg = support.UnwindRegSp
				info.AuxParam = 0
			}
		}
		bb.Deltas.Add(uint32(pc), info)
	}
}

func resolveCUStrategies(g *Gopclntab,
	getSourceFileStrategy func(sourceFile string) strategy) (map[int]strategy, error) {
	rdr := pfbufio.Reader{}
	defer rdr.Release()

	// Walk all filenames and record the ones needing a strategy
	offsetStrategy := make(map[int]strategy)
	rdr.InitSlideView(g.readerAt, g.pclntabOffset+g.filetabOffset, g.pctabOffset-g.filetabOffset)
	err := rdr.WalkStrings(int(g.numFiles), func(offs int64, filename string) error {
		if s := getSourceFileStrategy(filename); s != strategyUnknown {
			offsetStrategy[int(offs)] = s
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Walk cutab indexes and map them to strategy
	cuStrategy := make(map[int]strategy)
	rdr.InitSlideView(g.readerAt, g.pclntabOffset+g.cuOffset, g.filetabOffset-g.cuOffset)
	var offset uint32
	for idx := 0; ; idx++ {
		if _, err = rdr.Read(pfunsafe.FromPointer(&offset)); err != nil {
			if err != io.EOF {
				return nil, err
			}
			break
		}
		if s, ok := offsetStrategy[int(offset)]; ok {
			cuStrategy[idx] = s
		}
	}

	return cuStrategy, nil
}

func resolveFunctionUnwindInfo(r io.ReaderAt, g *Gopclntab, arch elf.Machine, useFP bool) (map[int32]*sdtypes.UnwindInfo, error) {
	rdr := pfbufio.Reader{}
	defer rdr.Release()

	functionInfo := make(map[int32]*sdtypes.UnwindInfo)
	rdr.InitSlideView(r, g.pclntabOffset+g.funcnameOffset, g.cuOffset-g.funcnameOffset)
	err := rdr.WalkAllStrings(func(offs int64, funcName string) error {
		if info := getFunctionUnwindInfo(funcName, arch, useFP); info != nil {
			functionInfo[int32(offs)] = info
		}
		return nil
	})
	return functionInfo, err
}

// Parse Golang .gopclntab spdelta tables and try to produce minified intervals
// by using large frame pointer ranges when possible
func (ee *elfExtractor) parseGoPclntab() error {
	if !ee.file.IsGolang() {
		return nil
	}
	g, err := NewGopclntab(ee.file)
	if err != nil {
		return err
	}
	defer g.Close()

	// Get target machine architecture for the ELF file
	arch := ee.file.Machine
	defaultStrategy := strategyFramePointer
	useFP := true
	pcspMinimumValue := int32(0)
	var parsePcsp func(bb *sdtypes.BasicBlock, p *pcvalDecoder, s strategy) error
	var cuStrategy map[int]strategy

	switch arch {
	case elf.EM_X86_64:
		parsePcsp = parseX86pcspFunc
		// Golang generates pcsp delta -8 for syscall.rawVforkSyscall which
		// pops the return address for the duration of the syscall. Allow this
		// to parse the table, and in most cases the popped out stack value is
		// still the real return address.
		pcspMinimumValue = -8
		// Go uses frame-pointers by default since Go 1.7, but unfortunately
		// it is not necessarily available when in code from non-Golang source
		// files, such as the assembly, of the Go runtime.
		// Since Golang binaries are huge statically compiled executables and
		// would fill up our precious kernel delta maps fast, the strategy is to
		// create deltastack maps for non-Go source files only, and otherwise
		// cover the vast majority with "use frame pointer" stack delta.
		cuStrategy, err = resolveCUStrategies(g, getSourceFileStrategyX86)
		if err != nil {
			return fmt.Errorf("cutab: %v", err)
		}
	case elf.EM_AARCH64:
		parsePcsp = parseArm64pcspFunc
		// Golang generates pcsp delta -16 for functions that restore the
		// caller's FP/LR pair before the end of the function, e.g.
		// runtime.asyncPreempt and runtime.debugCallV2.
		pcspMinimumValue = -16
		// Go 1.20 and earlier did not maintain frame pointers properly on arm64.
		// This was fixed for Go 1.21 and later in:
		// https://github.com/golang/go/commit/a41a29ad19c25c3475a65b7265fcad870d954c2a
		switch g.version {
		case go1_16, go1_18:
			// Magic indicates old Go with broken arm64 frame pointers
			defaultStrategy = strategyDeltasWithFrame
			useFP = false
		case go1_20:
			// Ambiguous regarding if frame pointer is kept correctly.
			// Take the slow path of resolving Go version.
			goVer := ee.file.GoVersion()
			if goVer == "" || version.Compare(goVer, "go1.21rc1") < 0 {
				defaultStrategy = strategyDeltasWithFrame
				useFP = false
			}
		}
	default:
		return fmt.Errorf("unsupported ELF architecture (%x)", arch)
	}

	funcUnwindInfo, err := resolveFunctionUnwindInfo(ee.file.Underlying(), g, arch, useFP)
	if err != nil {
		return fmt.Errorf("funcnametab: %v", err)
	}

	maxPcfileOff := int32(0)
	firstFileIndex := make(map[int32]int32)

	start, end, err := g.walkFuncMap(func(pc, endPc uint64, fun *pclntabFunc) error {
		bb := sdtypes.BasicBlock{
			Start: pc,
			End:   endPc,
		}

		// First, check for functions with special handling.
		if info, ok := funcUnwindInfo[int32(fun.nameOff)]; ok {
			bb.Deltas.Add(0, *info)
			ee.intervals.Add(bb)
			return nil
		}

		// Use source file to determine strategy if possible, and default
		// to using frame pointers in the unlikely case of no file info
		fileStrategy := defaultStrategy
		if fun.pcfileOff != 0 {
			val, ok := firstFileIndex[fun.pcfileOff]
			if !ok {
				val, err = g.pcval.getFirst(fun.pcfileOff)
				if err != nil {
					return fmt.Errorf("func %x pcfileOff: %w", pc, err)
				}
				if fun.pcfileOff < maxPcfileOff {
					firstFileIndex[fun.pcfileOff] = val
				} else {
					maxPcfileOff = fun.pcfileOff
				}
			}
			cuIndex := int(fun.npcData) + int(val)
			if s, ok := cuStrategy[cuIndex]; ok {
				fileStrategy = s
			}
		}

		if fileStrategy == strategyFramePointer {
			// Use stack frame-pointer delta
			bb.Deltas.Add(0, sdtypes.UnwindInfoFramePointer)
			ee.intervals.Add(bb)
			return nil
		}

		if fun.pcspOff == 0 {
			// Some functions don't have PCSP info: skip them.
			return nil
		}

		// Generate stack deltas as the information is available
		g.pcval.reset(fun.pcspOff, pcspMinimumValue)
		if err := parsePcsp(&bb, &g.pcval, fileStrategy); err != io.EOF {
			return err
		}
		ee.intervals.Add(bb)
		return nil
	})
	if start != end {
		// Filter out .gopclntab info from other sources
		ee.hooks.golangHook(uintptr(start), uintptr(end))
	}
	return err
}
