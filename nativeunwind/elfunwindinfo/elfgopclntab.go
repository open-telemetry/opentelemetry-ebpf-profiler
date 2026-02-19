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

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfatbuf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Go runtime functions for which we should not attempt to unwind further
var goFunctionsStopDelta = map[string]*sdtypes.UnwindInfo{
	"runtime.mstart": &sdtypes.UnwindInfoStop, // topmost for the go runtime main stacks
	"runtime.goexit": &sdtypes.UnwindInfoStop, // return address in all goroutine stacks

	// stack switch functions that would need special handling for further unwinding.
	// See PF-1101.
	"runtime.mcall":       &sdtypes.UnwindInfoStop,
	"runtime.systemstack": &sdtypes.UnwindInfoStop,

	// signal return frame
	"runtime.sigreturn":            &sdtypes.UnwindInfoSignal,
	"runtime.sigreturn__sigaction": &sdtypes.UnwindInfoSignal,
}

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

// pclntabHeader is the Golang pclntab header structure
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
}

// pclntabHeader116 is the Golang pclntab additional header starting Go 1.16
// structural definition of this is found in go/src/runtime/symtab.go as pcHeader
type pclntabHeader116 struct {
	nfiles         uint
	funcnameOffset int64
	cuOffset       int64
	filetabOffset  int64
	pctabOffset    int64
	pclnOffset     int64
}

// pclntabHeader118 is the Golang pclntab additional header starting Go 1.18
// structural definition of this is found in go/src/runtime/symtab.go as pcHeader
type pclntabHeader118 struct {
	nfiles         uint
	textStart      uint64
	funcnameOffset int64
	cuOffset       int64
	filetabOffset  int64
	pctabOffset    int64
	pclnOffset     int64
}

// pclntabFuncMap is the Golang function symbol table map entry
type pclntabFuncMap struct {
	pc      uint64
	funcOff int64
}

// pclntabFuncMap118 is the Golang function symbol table map entry for Go 1.18+.
type pclntabFuncMap118 struct {
	pc      uint32
	funcOff uint32
}

// pclntabFunc is the common portion of the Golang function definition.
type pclntabFunc struct {
	// The actual data is preceded with the function start PC value, which is
	// a pointer (pre-Go1.18) or fixed 32-bit offset from .text start (Go1.18+).
	// startPc                   uintptr | uint32
	nameOff, argsSize, frameSize int32
	pcspOff, pcfileOff, pclnOff  int32
	nfuncData, npcData           int32
}

// pcval describes a Program Counter (pc) and a value (val) associated with it,
// as well as the slice containing the full pcval data. The meaning of the value
// depends on which table is being processed. It can signify the Stack Delta in
// bytes, the source filename index, or the source line number.
type pcval struct {
	rd      *pfatbuf.Cache
	data    []byte
	offs    int64
	pcStart uint
	pcEnd   uint
	val     int32
	quantum uint8
	eof     bool
}

// PclntabHeaderSize returns the minimal pclntab header size.
func PclntabHeaderSize() int {
	return int(unsafe.Sizeof(pclntabHeader{}))
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

	return []byte{0, 0xff, 0xff, 0xff, 0x00, 0x00, quantum, 0x08}
}

func newPcval(rd *pfatbuf.Cache, offs int64, pc uint, quantum uint8) pcval {
	p := pcval{
		rd:      rd,
		offs:    offs,
		pcEnd:   pc,
		val:     -1,
		quantum: quantum,
	}
	p.step()
	return p
}

// getByte reads one byte
func (p *pcval) getByte() byte {
	if len(p.data) == 0 {
		if p.eof {
			return 0
		}
		data, err := p.rd.UnsafeReadAt(1, p.offs)
		if len(data) == 0 || err != nil {
			p.eof = true
			return 0
		}
		p.data = data
	}
	p.offs++
	b := p.data[0]
	p.data = p.data[1:]
	return b
}

// getInt reads one zig-zag encoded integer
func (p *pcval) getInt() uint32 {
	var v, shift uint32
	for {
		b := p.getByte()
		v |= (uint32(b) & 0x7F) << shift
		if b&0x80 == 0 {
			break
		}
		shift += 7
	}
	return v
}

// step executes one line of the pcval table. Returns true on success.
func (p *pcval) step() bool {
	d := p.getInt()
	if d == 0 {
		return false
	}
	p.pcStart = p.pcEnd
	if d&1 != 0 {
		d = ^(d >> 1)
	} else {
		d >>= 1
	}
	p.val += int32(d)
	p.pcEnd += uint(p.getInt()) * uint(p.quantum)
	return true
}

// searchGoPclntab uses heuristic to find the gopclntab from RO data.
func searchGoPclntab(ef *pfelf.File, notFound error) (io.ReaderAt, int64, error) {
	// The sections headers are not available for coredump testing, because they are
	// not inside any PT_LOAD segment. And in the case ofwhere they might be available
	// because of alignment they are likely not usable, e.g. the musl C-library will
	// reuse that area via malloc.
	//
	// Go does emit "runtime.pclntab" and "runtime.epclntab" symbols of the .gopclntab
	// too, but these are not dynamic, and we'd need the full symbol table from
	// the .symtab section to get them. This means that these symbols are not present
	// in the symbol hash table, nor in the .dynsym symbol table available via dynamic
	// section.
	//
	// So the only thing that works for ELF files inside core dump files is to use
	// a heuristic to find the .gopclntab from the RO data segment based on its header.

	signature := pclntabHeaderSignature(ef.Machine)
	for i := range ef.Progs {
		p := &ef.Progs[i]
		// Search for the .rodata (read-only) and .data.rel.ro (read-write which gets
		// turned into read-only after relocations handling via GNU_RELRO header).
		if p.Type != elf.PT_LOAD || p.Flags&elf.PF_X == elf.PF_X || p.Flags&elf.PF_R != elf.PF_R {
			continue
		}

		var buf [64 * 1024]byte
		for offs := int64(0); offs+int64(PclntabHeaderSize()) < int64(p.Filesz); {
			n, err := p.ReadAt(buf[:], offs)
			for x := 0; x+len(signature) < n; x += len(signature) {
				if !bytes.Equal(signature[1:], buf[x+1:x+len(signature)]) {
					continue
				}
				// Check the 'magic' against supported list, and if valid, use this
				// location as the .gopclntab base. Otherwise, continue just search
				// for next candidate location.
				magic := binary.LittleEndian.Uint32(buf[x:])
				if goMagicToVersion(magic) != goInvalid {
					offs += int64(x)
					maxSize := int64(p.Filesz) - offs
					return io.NewSectionReader(p, offs, maxSize), maxSize, nil
				}
			}
			if err != nil {
				break
			}
			offs += int64(n - len(signature))
		}
	}
	return nil, 0, notFound
}

var errFailedToFindGopclntab = errors.New("failed to find .gopclntab on go binary")

// extractGoPclntab extracts the .gopclntab reader from a given pfelf.File.
func extractGoPclntab(ef *pfelf.File) (data io.ReaderAt, maxSz int64, err error) {
	if ef.InsideCore {
		// Section tables not available. Use heuristic. Ignore errors as
		// this might not be a Go binary.
		return searchGoPclntab(ef, nil)
	}
	if s := ef.Section(".gopclntab"); s != nil {
		// Load the .gopclntab via section if available.
		return s, int64(s.FileSize), nil
	}
	if s := ef.Section(".go.buildinfo"); s != nil {
		// This looks like Go binary. Lookup the runtime.pclntab symbols,
		// as the .gopclntab section is not available on PIE binaries.
		// A full symbol table read is needed as these are not dynamic symbols.
		// Consequently these symbols might be unavailable on a stripped binary.
		var start, end int64
		ef.VisitSymbols(func(sym libpf.Symbol) bool {
			if sym.Name == "runtime.pclntab" {
				start = int64(sym.Address)
			} else if sym.Name == "runtime.epclntab" {
				end = int64(sym.Address)
			}
			return start == 0 || end == 0
		})
		if start == 0 || end == 0 {
			// It seems the Go binary was stripped. So we use the heuristic approach
			// to get the stack deltas.
			return searchGoPclntab(ef, errFailedToFindGopclntab)
		}
		if start >= end {
			return nil, 0, fmt.Errorf("invalid .gopclntab symbols: %v-%v", start, end)
		}
		return io.NewSectionReader(ef, start, end-start), end - start, nil
	}
	return nil, 0, nil
}

// Gopclntab is the API for extracting data from .gopclntab
type Gopclntab struct {
	ef            *pfelf.File
	cache         pfatbuf.Cache
	cutabCache    pfatbuf.Cache
	funcMapCache  pfatbuf.Cache
	funcNameCache pfatbuf.Cache

	textStart uint64
	numFuncs  int
	numFiles  uint

	version     uint8
	quantum     uint8
	ptrSize     uint8
	funSize     uint8
	funcMapSize uint8

	// These are offsets to various areas within .gopclntab
	functab, funcdata, funcnametab, filetab, pctab, cutab int64
}

// LookupSymbol searches for a given symbol in .gopclntab.
func (g *Gopclntab) LookupSymbol(symbol libpf.SymbolName) (*libpf.Symbol, error) {
	symString := string(symbol)
	for i := 0; i < g.numFuncs; i++ {
		_, funcOff := g.getFuncMapEntry(i)
		pc, fun := g.getFunc(funcOff)
		if pc == 0 {
			continue
		}
		name, _ := g.funcNameCache.UnsafeStringAt(g.funcnametab+int64(fun.nameOff), len(symbol))
		if name == symString {
			nextPc, _ := g.getFuncMapEntry(i + 1)
			size := uint64(nextPc - pc)

			return &libpf.Symbol{
				Name:    symbol,
				Address: libpf.SymbolValue(pc),
				Size:    size,
			}, nil
		}
	}
	return nil, libpf.ErrSymbolNotFound
}

// NewGopclntab parses and returns the parsed data for further operations.
func NewGopclntab(ef *pfelf.File) (*Gopclntab, error) {
	rdr, dataLen, err := extractGoPclntab(ef)
	if rdr == nil || err != nil {
		return nil, err
	}

	g := &Gopclntab{}
	g.cache.InitName("go.cache", rdr)
	g.cutabCache.InitName("go.cutab", rdr)
	g.funcMapCache.InitName("go.funcMap", rdr)
	g.funcNameCache.InitName("go.funcName", rdr)

	hdrSize := int64(PclntabHeaderSize())
	var hdr pclntabHeader
	if _, err = g.cache.ReadAt(pfunsafe.FromPointer(&hdr), 0); err != nil {
		return nil, fmt.Errorf("failed to read .gopclntab header: %w", err)
	}
	g.version = goMagicToVersion(hdr.magic)
	g.quantum = hdr.quantum
	g.ptrSize = hdr.ptrSize
	g.funSize = hdr.ptrSize + uint8(unsafe.Sizeof(pclntabFunc{}))
	g.funcMapSize = hdr.ptrSize * 2
	g.numFuncs = int(hdr.numFuncs)

	if g.version == goInvalid || hdr.pad != 0 || hdr.ptrSize != 8 {
		return nil, fmt.Errorf(".gopclntab header: %x, %x, %x", hdr.magic, hdr.pad, hdr.ptrSize)
	}

	switch g.version {
	case go1_2:
		functabEnd := uint64(hdrSize) + uint64(g.numFuncs)*uint64(g.funcMapSize) + uint64(hdr.ptrSize)
		filetabOffset := g.cache.Uint32At(int64(functabEnd))
		g.numFiles = uint(g.cache.Uint32At(int64(filetabOffset)))
		if filetabOffset == 0 || g.numFiles == 0 {
			return nil, fmt.Errorf(".gopclntab corrupt (filetab 0x%x, nfiles %d)",
				filetabOffset, g.numFiles)
		}
		g.functab = int64(hdrSize)
		g.cutab = int64(filetabOffset)
	case go1_16:
		var hdr116 pclntabHeader116
		if _, err = g.cache.ReadAt(pfunsafe.FromPointer(&hdr116), hdrSize); err != nil {
			return nil, fmt.Errorf("failed to read .gopclntab header: %w", err)
		}
		if dataLen < hdr116.funcnameOffset || dataLen < hdr116.cuOffset ||
			dataLen < hdr116.filetabOffset || dataLen < hdr116.pctabOffset ||
			dataLen < hdr116.pclnOffset {
			return nil, fmt.Errorf(".gopclntab is corrupt (%x, %x, %x, %x, %x)",
				hdr116.funcnameOffset, hdr116.cuOffset,
				hdr116.filetabOffset, hdr116.pctabOffset,
				hdr116.pclnOffset)
		}
		g.numFiles = hdr116.nfiles
		g.funcnametab = hdr116.funcnameOffset
		g.cutab = hdr116.cuOffset
		g.filetab = hdr116.filetabOffset
		g.pctab = hdr116.pctabOffset
		g.functab = hdr116.pclnOffset
		g.funcdata = g.functab
	case go1_18, go1_20:
		var hdr118 pclntabHeader118
		if _, err = g.cache.ReadAt(pfunsafe.FromPointer(&hdr118), hdrSize); err != nil {
			return nil, fmt.Errorf("failed to read .gopclntab header: %w", err)
		}
		if dataLen < hdr118.funcnameOffset || dataLen < hdr118.cuOffset ||
			dataLen < hdr118.filetabOffset || dataLen < hdr118.pctabOffset ||
			dataLen < hdr118.pclnOffset {
			return nil, fmt.Errorf(".gopclntab is corrupt (%x, %x, %x, %x, %x)",
				hdr118.funcnameOffset, hdr118.cuOffset,
				hdr118.filetabOffset, hdr118.pctabOffset,
				hdr118.pclnOffset)
		}
		g.numFiles = hdr118.nfiles
		g.funcnametab = hdr118.funcnameOffset
		g.cutab = hdr118.cuOffset
		g.filetab = hdr118.filetabOffset
		g.pctab = hdr118.pctabOffset
		g.functab = hdr118.pclnOffset
		g.funcdata = g.functab
		g.textStart = hdr118.textStart
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
	}
	g.ef = ef.Take()
	return g, nil
}

// Close releases the pfelf Data reference taken.
func (g *Gopclntab) Close() error {
	return g.ef.Close()
}

// getFuncMapEntry returns the entry at 'index' from the gopclntab function lookup map.
func (g *Gopclntab) getFuncMapEntry(index int) (pc uint64, funcOff int64) {
	offs := g.functab + int64(index*int(g.funcMapSize))
	data, err := g.funcMapCache.UnsafeReadAt(int(g.funcMapSize), offs)
	if err != nil {
		return 0, 0
	}
	if g.version >= go1_18 {
		//nolint:lll
		// See: https://github.com/golang/go/blob/6df0957060b1315db4fd6a359eefc3ee92fcc198/src/debug/gosym/pclntab.go#L401-L413
		fmap := (*pclntabFuncMap118)(unsafe.Pointer(unsafe.SliceData(data)))
		return g.textStart + uint64(fmap.pc), int64(fmap.funcOff)
	} else {
		fmap := (*pclntabFuncMap)(unsafe.Pointer(unsafe.SliceData(data)))
		return fmap.pc, fmap.funcOff
	}
	return 0, 0
}

// getFunc returns the gopclntab function data and its start address.
func (g *Gopclntab) getFunc(funcOff int64) (pc uint64, fun pclntabFunc) {
	data, err := g.cache.UnsafeReadAt(int(g.funSize), g.funcdata+funcOff)
	if err != nil {
		return 0, pclntabFunc{}
	}
	if g.version >= go1_18 {
		pc = g.textStart + uint64(binary.LittleEndian.Uint32(data))
		data = data[4:]
	} else {
		pc = g.textStart + binary.LittleEndian.Uint64(data)
		data = data[8:]
	}
	return pc, *(*pclntabFunc)(unsafe.Pointer(unsafe.SliceData(data)))
}

// getPcval returns the pcval table at given offset with 'startPc' as the pc start value.
func (g *Gopclntab) getPcval(offs int32, startPc uint) pcval {
	return newPcval(&g.cache, int64(g.pctab)+int64(offs), startPc, g.quantum)
}

// mapPcval steps the given pcval table until matching PC is found and returns the value.
func (g *Gopclntab) mapPcval(offs int32, startPc, pc uint) (int32, bool) {
	p := g.getPcval(offs, startPc)
	for ok := true; ok; ok = p.step() {
		if p.pcEnd > pc {
			return p.val, true
		}
	}
	return 0, false
}

// Symbolize returns the file, line and function information for given PC
func (g *Gopclntab) Symbolize(pc uint64) (sourceFile libpf.String, line uint, funcName libpf.String) {
	index := sort.Search(int(g.numFuncs), func(i int) bool {
		funcPc, _ := g.getFuncMapEntry(i)
		return funcPc > pc
	}) - 1
	if index < 0 || index >= g.numFuncs {
		return libpf.NullString, 0, libpf.NullString
	}

	mapPc, funcOff := g.getFuncMapEntry(index)
	funcPc, fun := g.getFunc(funcOff)
	if mapPc != funcPc {
		return libpf.NullString, 0, libpf.NullString
	}
	funcName, _ = g.funcNameCache.InternStringAt(int64(g.funcnametab) + int64(fun.nameOff))
	if fun.pcfileOff != 0 {
		if fileIndex, ok := g.mapPcval(fun.pcfileOff, uint(funcPc), uint(pc)); ok {
			if g.version >= go1_16 {
				fileIndex += fun.npcData
			}
			fileOffs := int64(g.cutabCache.Uint32At(g.cutab + 4*int64(fileIndex)))
			sourceFile, _ = g.cache.InternStringAt(g.filetab + fileOffs)
		}
	}
	if fun.pclnOff != 0 {
		lineNo, _ := g.mapPcval(fun.pclnOff, uint(funcPc), uint(pc))
		line = uint(lineNo)
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

type strategy int

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

// Go uses frame-pointers by default since Go 1.7, but unfortunately
// it is not necessarily available when in code from non-Golang source
// files, such as the assembly, of the Go runtime.
// Since Golang binaries are huge statically compiled executables and
// would fill up our precious kernel delta maps fast, the strategy is to
// create deltastack maps for non-Go source files only, and otherwise
// cover the vast majority with "use frame pointer" stack delta.
func getX86SourceFileStrategy(sourceFile string) strategy {
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

func resolveX86SourceFileStrategies(g *Gopclntab) map[uint32]strategy {
	cache := make(map[uint32]strategy)
	filetabCache := pfatbuf.Cache{}
	filetabCache.InitName("go.filetab", g.cache.Inner())

	offs := uint32(0)
	for range g.numFiles {
		sourceFile, _ := filetabCache.UnsafeStringAt(g.filetab+int64(offs), 256)
		if s := getX86SourceFileStrategy(sourceFile); s != strategyUnknown {
			cache[offs] = s
		}
		offs += uint32(len(sourceFile)) + 1
	}
	return cache
}

// parseX86pclntabFunc extracts interval information from x86_64 based pclntabFunc.
func parseX86pclntabFunc(deltas *sdtypes.StackDeltaArray, p pcval, s strategy) error {
	hints := sdtypes.UnwindHintKeep
	for ok := true; ok; ok = p.step() {
		info := sdtypes.UnwindInfo{
			BaseReg: support.UnwindRegSp,
			Param:   p.val + 8,
		}
		if s == strategyDeltasWithFrame && info.Param >= 16 {
			info.AuxBaseReg = support.UnwindRegCfa
			info.AuxParam = -16
		}
		deltas.Add(sdtypes.StackDelta{
			Address: uint64(p.pcStart),
			Hints:   hints,
			Info:    info,
		})
		hints = sdtypes.UnwindHintNone
	}
	return nil
}

// parseArm64pclntabFunc extracts interval information from ARM64 based pclntabFunc.
func parseArm64pclntabFunc(deltas *sdtypes.StackDeltaArray, p pcval, s strategy) error {
	hint := sdtypes.UnwindHintKeep
	for ok := true; ok; ok = p.step() {
		var info sdtypes.UnwindInfo
		if p.val == 0 {
			// Return instruction, function prologue or leaf function body: unwind via LR.
			info = sdtypes.UnwindInfoLR
		} else {
			// Regular basic block in the function body: unwind via SP.
			info = sdtypes.UnwindInfo{
				// Unwind via SP offset.
				BaseReg: support.UnwindRegSp,
				Param:   p.val,
			}
			if s == strategyDeltasWithFrame {
				// On ARM64, the previous LR value is stored to top-of-stack.
				info.AuxBaseReg = support.UnwindRegSp
				info.AuxParam = 0
			}
		}

		deltas.Add(sdtypes.StackDelta{
			Address: uint64(p.pcStart),
			Hints:   hint,
			Info:    info,
		})

		hint = sdtypes.UnwindHintNone
	}

	return nil
}

// Parse Golang .gopclntab spdelta tables and try to produce minified intervals
// by using large frame pointer ranges when possible
func (ee *elfExtractor) parseGoPclntab() error {
	g, err := NewGopclntab(ee.file)
	if g == nil || err != nil {
		return err
	}
	defer g.Close()

	// Get target machine architecture for the ELF file
	arch := ee.file.Machine
	defaultStrategy := strategyFramePointer
	pcfileOffToIndex := make(map[int32]uint32)
	var fileOffsToStrategy map[uint32]strategy
	var parsePclntab func(deltas *sdtypes.StackDeltaArray, p pcval, s strategy) error

	switch arch {
	case elf.EM_X86_64:
		parsePclntab = parseX86pclntabFunc
		fileOffsToStrategy = resolveX86SourceFileStrategies(g)
	case elf.EM_AARCH64:
		parsePclntab = parseArm64pclntabFunc
		// Go 1.20 and earlier did not maintain frame pointers properly on arm64.
		// This was fixed for Go 1.21 and later in:
		// https://github.com/golang/go/commit/a41a29ad19c25c3475a65b7265fcad870d954c2a
		switch g.version {
		case go1_2, go1_16, go1_18:
			// Magic indicates old Go with broken arm64 frame pointers
			defaultStrategy = strategyDeltasWithFrame
		case go1_20:
			// Ambiguous regarding if frame pointer is kept correctly.
			// Take the slow path of resolving Go version.
			goVer, err := ee.file.GoVersion()
			if err != nil || version.Compare(goVer, "go1.21rc1") < 0 {
				defaultStrategy = strategyDeltasWithFrame
			}
		}
	default:
		return fmt.Errorf("unsupported ELF architecture (%x)", arch)
	}

	// Iterate the golang PC to function lookup table (sorted by PC)
	pcfileOff := int32(0)
	start, _ := g.getFuncMapEntry(0)
	for i := 0; i < g.numFuncs; i++ {
		mapPc, funcOff := g.getFuncMapEntry(i)
		funcPc, fun := g.getFunc(funcOff)
		if mapPc != funcPc {
			return fmt.Errorf(".gopclntab func %v descriptor is invalid (pc %x/%x)",
				i, mapPc, funcPc)
		}

		// First, check for functions with special handling.
		funcName, _ := g.funcNameCache.UnsafeStringAt(g.funcnametab+int64(fun.nameOff), 32)
		if info, found := goFunctionsStopDelta[funcName]; found {
			ee.deltas.Add(sdtypes.StackDelta{
				Address: uint64(funcPc),
				Info:    *info,
			})
			continue
		}

		// Use source file to determine strategy if possible, and default
		// to using frame pointers in the unlikely case of no file info
		fileStrategy := defaultStrategy
		if fileOffsToStrategy != nil && fun.pcfileOff != 0 {
			fileIndex, ok := pcfileOffToIndex[fun.pcfileOff]
			if !ok {
				p := g.getPcval(fun.pcfileOff, uint(funcPc))
				fileIndex = uint32(p.val)
				if fun.pcfileOff < pcfileOff {
					// Backreference, likely to happen again, so memoize it
					pcfileOffToIndex[fun.pcfileOff] = fileIndex
				} else {
					pcfileOff = fun.pcfileOff
				}
			}

			if g.version >= go1_16 {
				fileIndex += uint32(fun.npcData)
			}
			fileOffs := g.cutabCache.Uint32At(g.cutab + int64(4*fileIndex))
			if s, ok := fileOffsToStrategy[fileOffs]; ok {
				fileStrategy = s
			}
		}

		if fileStrategy == strategyFramePointer {
			// Use stack frame-pointer delta
			ee.deltas.Add(sdtypes.StackDelta{
				Address: uint64(funcPc),
				Info:    sdtypes.UnwindInfoFramePointer,
			})
			continue
		}

		if fun.pcspOff == 0 {
			// Some functions don't have PCSP info: skip them.
			continue
		}

		// Generate stack deltas as the information is available
		p := g.getPcval(fun.pcspOff, uint(funcPc))
		if err := parsePclntab(ee.deltas, p, fileStrategy); err != nil {
			return err
		}
	}

	// Filter out .gopclntab info from other sources
	end, _ := g.getFuncMapEntry(int(g.numFuncs))
	ee.hooks.golangHook(uint64(start), uint64(end))

	// Add end of code indicator
	ee.deltas.Add(sdtypes.StackDelta{
		Address: uint64(end),
		Info:    sdtypes.UnwindInfoInvalid,
	})

	return nil
}
