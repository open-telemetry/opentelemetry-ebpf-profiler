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
	"go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	// maximum pclntab (or rodata segment) size to inspect. The .gopclntab is
	// often huge. Host agent binaries have about 32M .rodata, so allow for more.
	maxBytesGoPclntab = 128 * 1024 * 1024

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

// errNoPclntab is returned if the file has no .gopclntab data and
// is therefore not a (or not a fully-intact) Go binary.
var errNoPclntab = errors.New("no gopclntab section found")

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

// pclntabHeader116 is the Golang pclntab header structure starting Go 1.16
// structural definition of this is found in go/src/runtime/symtab.go as pcHeader
type pclntabHeader116 struct {
	pclntabHeader
	nfiles         uint
	funcnameOffset uintptr
	cuOffset       uintptr
	filetabOffset  uintptr
	pctabOffset    uintptr
	pclnOffset     uintptr
}

// pclntabHeader118 is the Golang pclntab header structure starting Go 1.18
// structural definition of this is found in go/src/runtime/symtab.go as pcHeader
type pclntabHeader118 struct {
	pclntabHeader
	nfiles         uint
	textStart      uintptr
	funcnameOffset uintptr
	cuOffset       uintptr
	filetabOffset  uintptr
	pctabOffset    uintptr
	pclnOffset     uintptr
}

// pclntabFuncMap is the Golang function symbol table map entry
type pclntabFuncMap struct {
	pc      uintptr
	funcOff uintptr
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
	ptr     []byte
	pcStart uint
	pcEnd   uint
	val     int32
	quantum uint8
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

	return []byte{0xff, 0xff, 0xff, 0x00, 0x00, quantum, 0x08}
}

func newPcval(data []byte, pc uint, quantum uint8) pcval {
	p := pcval{
		ptr:     data,
		pcEnd:   pc,
		val:     -1,
		quantum: quantum,
	}
	p.step()
	return p
}

// getInt reads one zig-zag encoded integer
func (p *pcval) getInt() uint32 {
	var v, shift uint32
	for {
		if len(p.ptr) == 0 {
			return 0
		}
		b := p.ptr[0]
		p.ptr = p.ptr[1:]
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
	if len(p.ptr) == 0 || p.ptr[0] == 0 {
		return false
	}
	p.pcStart = p.pcEnd
	d := p.getInt()
	if d&1 != 0 {
		d = ^(d >> 1)
	} else {
		d >>= 1
	}
	p.val += int32(d)
	p.pcEnd += uint(p.getInt()) * uint(p.quantum)
	return true
}

// getInt32 gets a 32-bit integer from the data slice at offset with bounds checking
func getInt32(data []byte, offset int) int {
	if offset < 0 || offset+4 > len(data) {
		return -1
	}
	return int(*(*int32)(unsafe.Pointer(&data[offset])))
}

// getString returns a string from the data slice at given offset.
func getString(data []byte, offset int) string {
	if offset < 0 || offset > len(data) {
		return ""
	}
	zeroIdx := bytes.IndexByte(data[offset:], 0)
	if zeroIdx < 0 {
		return ""
	}
	return pfunsafe.ToString(data[offset : offset+zeroIdx])
}

// searchGoPclntab uses heuristic to find the gopclntab from RO data.
func searchGoPclntab(ef *pfelf.File) ([]byte, int64, error) {
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

		// Skip segments that are too small anyway.
		if p.Filesz < uint64(PclntabHeaderSize()) {
			continue
		}

		var data []byte
		var err error
		if data, err = p.Data(maxBytesGoPclntab); err != nil {
			return nil, 0, err
		}

		for i := 1; i < len(data)-PclntabHeaderSize(); i += 8 {
			// Search for something looking like a valid pclntabHeader header
			// Ignore the first byte on bytes.Index (differs on magicGo1_XXX)
			n := bytes.Index(data[i:], signature)
			if n < 0 {
				break
			}
			i += n - 1

			// Check the 'magic' against supported list, and if valid, use this
			// location as the .gopclntab base. Otherwise, continue just search
			// for next candidate location.
			hdr := (*pclntabHeader)(unsafe.Pointer(&data[i]))
			if goMagicToVersion(hdr.magic) != goInvalid {
				return data[i:], int64(p.Off) + int64(i), nil
			}
		}
	}

	return nil, 0, nil
}

// extractGoPclntab extracts the .gopclntab data from a given pfelf.File.
func extractGoPclntab(ef *pfelf.File) (data []byte, offset int64, err error) {
	if ef.InsideCore {
		// Section tables not available. Use heuristic. Ignore errors as
		// this might not be a Go binary.
		data, offset, _ = searchGoPclntab(ef)
	} else if s := ef.Section(".gopclntab"); s != nil {
		// Load the .gopclntab via section if available.
		if data, err = s.Data(maxBytesGoPclntab); err != nil {
			return nil, 0, fmt.Errorf("failed to load .gopclntab section: %v", err)
		}
		offset = int64(s.Offset)
	} else if s := ef.Section(".go.buildinfo"); s != nil {
		// This looks like Go binary. Lookup the runtime.pclntab symbols,
		// as the .gopclntab section is not available on PIE binaries.
		// A full symbol table read is needed as these are not dynamic symbols.
		// Consequently these symbols might be unavailable on a stripped binary.
		var start, end libpf.SymbolValue
		ef.VisitSymbols(func(sym libpf.Symbol) bool {
			if sym.Name == "runtime.pclntab" {
				start = sym.Address
			} else if sym.Name == "runtime.epclntab" {
				end = sym.Address
			}
			return start == 0 || end == 0
		})
		if start == 0 || end == 0 {
			// It seems the Go binary was stripped. So we use the heuristic approach
			// to get the stack deltas.
			if data, offset, err = searchGoPclntab(ef); err != nil {
				return nil, 0, fmt.Errorf("failed to search .gopclntab: %v", err)
			}
		} else {
			if start >= end {
				return nil, 0, fmt.Errorf("invalid .gopclntab symbols: %v-%v", start, end)
			}
			data, err = ef.VirtualMemory(int64(start), int(end-start), maxBytesGoPclntab)
			if err != nil {
				return nil, 0, fmt.Errorf("failed to load .gopclntab via symbols: %v", err)
			}
			offset = int64(start)
		}
	}
	return data, offset, nil
}

// Gopclntab is the API for extracting data from .gopclntab
type Gopclntab struct {
	dataRef      io.Closer
	setDontNeed  func()
	headerOffset int64

	data      []byte
	textStart uintptr
	numFuncs  int
	numFiles  uint

	version     uint8
	quantum     uint8
	ptrSize     uint8
	funSize     uint8
	funcMapSize uint8

	funcnameOffset uintptr
	cuOffset       uintptr
	filetabOffset  uintptr
	pctabOffset    uintptr
	pclnOffset     uintptr

	// These are read-only byte slices to various areas within .gopclntab
	// (subslices of data []byte). Since 'data' a slice returned by pfelf.File
	// it can be allocated or mmapped read-only data. To keep memory usage
	// and GC stress minimal the returned strings (symbol and file names) refer
	// to this data directly (via unsafe.String).
	functab, funcnametab, filetab, pctab, cutab []byte
}

// LookupSymbol searches for a given symbol in .gopclntab.
func (g *Gopclntab) LookupSymbol(symbol libpf.SymbolName) (*libpf.Symbol, error) {
	symString := string(symbol)
	for i := 0; i < g.numFuncs; i++ {
		_, funcOff := g.getFuncMapEntry(i)
		pc, fun := g.getFunc(funcOff)
		if fun == nil {
			continue
		}
		name := getString(g.funcnametab, int(fun.nameOff))
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
// Returns ErrNoPclntab when the file contains no gopclntab data.
func NewGopclntab(ef *pfelf.File) (*Gopclntab, error) {
	data, headerOffset, err := extractGoPclntab(ef)
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, errNoPclntab
	}
	defer ef.SetDontNeed()

	hdrSize := uintptr(PclntabHeaderSize())
	dataLen := uintptr(len(data))
	if dataLen < hdrSize {
		return nil, fmt.Errorf(".gopclntab is too short (%v)", len(data))
	}

	hdr := (*pclntabHeader)(unsafe.Pointer(&data[0]))
	g := &Gopclntab{
		headerOffset: headerOffset,
		data:         data,
		version:      goMagicToVersion(hdr.magic),
		quantum:      hdr.quantum,
		ptrSize:      hdr.ptrSize,
		funSize:      hdr.ptrSize + uint8(unsafe.Sizeof(pclntabFunc{})),
		funcMapSize:  hdr.ptrSize * 2,
		numFuncs:     int(hdr.numFuncs),
	}
	if g.version == goInvalid || hdr.pad != 0 || hdr.ptrSize != 8 {
		return nil, fmt.Errorf(".gopclntab header: %x, %x, %x", hdr.magic, hdr.pad, hdr.ptrSize)
	}

	switch g.version {
	case go1_16:
		hdrSize = unsafe.Sizeof(pclntabHeader116{})
		if dataLen < hdrSize {
			return nil, fmt.Errorf(".gopclntab is too short (%v)", len(data))
		}
		hdr116 := (*pclntabHeader116)(unsafe.Pointer(&data[0]))
		g.numFiles = hdr116.nfiles
		g.funcnameOffset = hdr116.funcnameOffset
		g.cuOffset = hdr116.cuOffset
		g.filetabOffset = hdr116.filetabOffset
		g.pctabOffset = hdr116.pctabOffset
		g.pclnOffset = hdr116.pclnOffset
	case go1_18, go1_20:
		hdrSize = unsafe.Sizeof(pclntabHeader118{})
		if dataLen < hdrSize {
			return nil, fmt.Errorf(".gopclntab is too short (%v)", dataLen)
		}
		hdr118 := (*pclntabHeader118)(unsafe.Pointer(&data[0]))
		g.numFiles = hdr118.nfiles
		g.funcnameOffset = hdr118.funcnameOffset
		g.cuOffset = hdr118.cuOffset
		g.filetabOffset = hdr118.filetabOffset
		g.pctabOffset = hdr118.pctabOffset
		g.pclnOffset = hdr118.pclnOffset
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
	default:
		return nil, fmt.Errorf("unsupported goplntab version (%x)", hdr.magic)
	}

	if g.funcnameOffset >= g.cuOffset ||
		g.cuOffset >= g.filetabOffset ||
		g.filetabOffset >= g.pctabOffset ||
		g.pctabOffset >= g.pclnOffset ||
		g.pclnOffset >= dataLen {
		return nil, fmt.Errorf("gopclntab is corrupt (%x, %x, %x, %x, %x)",
			g.funcnameOffset, g.cuOffset,
			g.filetabOffset, g.pctabOffset,
			g.pclnOffset)
	}

	g.funcnametab = data[g.funcnameOffset:]
	g.cutab = data[g.cuOffset:]
	g.filetab = data[g.filetabOffset:]
	g.pctab = data[g.pctabOffset:]
	g.functab = data[g.pclnOffset:]

	g.dataRef = ef.Take()
	g.setDontNeed = ef.SetDontNeed

	return g, nil
}

// SetDontNeed gives advice about further use of memory.
func (g *Gopclntab) SetDontNeed() error {
	g.setDontNeed()
	return nil
}

// Close releases the pfelf Data reference taken.
func (g *Gopclntab) Close() error {
	return g.dataRef.Close()
}

// getFuncMapEntry returns the entry at 'index' from the gopclntab function lookup map.
func (g *Gopclntab) getFuncMapEntry(index int) (pc, funcOff uintptr) {
	if g.version >= go1_18 {
		//nolint:lll
		// See: https://github.com/golang/go/blob/6df0957060b1315db4fd6a359eefc3ee92fcc198/src/debug/gosym/pclntab.go#L401-L413
		fmap := (*pclntabFuncMap118)(unsafe.Pointer(&g.functab[index*int(g.funcMapSize)]))
		return g.textStart + uintptr(fmap.pc), uintptr(fmap.funcOff)
	} else {
		fmap := (*pclntabFuncMap)(unsafe.Pointer(&g.functab[index*int(g.funcMapSize)]))
		return fmap.pc, fmap.funcOff
	}
}

// getFunc returns the gopclntab function data and its start address.
func (g *Gopclntab) getFunc(funcOff uintptr) (uintptr, *pclntabFunc) {
	// Get the function data
	if uintptr(len(g.functab)) < funcOff+uintptr(g.funSize) {
		return 0, nil
	}
	var pc uintptr
	if g.version >= go1_18 {
		pc = g.textStart + uintptr(*(*uint32)(unsafe.Pointer(&g.functab[funcOff])))
		funcOff += 4
	} else {
		pc = *(*uintptr)(unsafe.Pointer(&g.functab[funcOff]))
		funcOff += uintptr(g.ptrSize)
	}
	return pc, (*pclntabFunc)(unsafe.Pointer(&g.functab[funcOff]))
}

// getPcval returns the pcval table at given offset with 'startPc' as the pc start value.
func (g *Gopclntab) getPcval(offs int32, startPc uint) pcval {
	return newPcval(g.pctab[int(offs):], startPc, g.quantum)
}

// mapPcval steps the given pcval table until matching PC is found and returns the value.
func (g *Gopclntab) mapPcval(offs int32, startPc, pc uint) (int32, bool) {
	p := g.getPcval(offs, startPc)
	for pc >= p.pcEnd {
		if ok := p.step(); !ok {
			return 0, false
		}
	}
	return p.val, true
}

// Symbolize returns the file, line and function information for given PC
func (g *Gopclntab) Symbolize(pc uintptr) (sourceFile string, line uint, funcName string) {
	// Binary search for the matching go function maps entry. The search
	// lambda makes 'sort.Search' return the first entry that is larger
	// than the pc. Thus -1 is needed to get index for the first entry
	// which is equal or less than pc. The gopclntab has an extra entry in
	// the end to indicate the end of Go code, use that to determine
	// if the pc is higher than any Go function address.
	index := sort.Search(g.numFuncs+1, func(i int) bool {
		funcPc, _ := g.getFuncMapEntry(i)
		return funcPc > pc
	}) - 1
	if index >= g.numFuncs || index < 0 {
		return "", 0, ""
	}

	mapPc, funcOff := g.getFuncMapEntry(index)
	funcPc, fun := g.getFunc(funcOff)
	if fun == nil || mapPc != funcPc {
		return "", 0, ""
	}

	funcName = getString(g.funcnametab, int(fun.nameOff))
	if fun.pcfileOff != 0 {
		if fileIndex, ok := g.mapPcval(fun.pcfileOff, uint(funcPc), uint(pc)); ok {
			sourceFile = getString(g.filetab, getInt32(g.cutab, 4*int(fileIndex+fun.npcData)))
		}
	}
	if fun.pclnOff != 0 {
		lineNo, _ := g.mapPcval(fun.pclnOff, uint(funcPc), uint(pc))
		line = uint(lineNo)
	}
	return sourceFile, line, funcName
}

func findTextStart(ef *pfelf.File) (uintptr, error) {
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

	return uintptr(binary.LittleEndian.Uint64(textBytes[:])), nil
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
func getFunctionUnwindInfo(sourceFile string, arch elf.Machine, framePointerReliable bool) *sdtypes.UnwindInfo {
	switch sourceFile {
	case "runtime.goexit", "runtime.mstart":
		// goexit - return address in all goroutine stacks
		// mstart - topmost for the go runtime main stacks
		return &sdtypes.UnwindInfoStop
	case "runtime.mcall": // unsupported at this time
		return &sdtypes.UnwindInfoStop
	case "runtime.asmcgocall":
		// asmcgocall FP is valid only on x86-64
		if arch != elf.EM_X86_64 {
			return &sdtypes.UnwindInfoStop
		}
		fallthrough
	case "runtime.systemstack", "runtime.nanotime1", "time.now", "runtime.walltime":
		// functions which preserve the frame pointer chain across the g0/user stack boundary
		// so that the standard FP unwinding traverses it naturally.
		if !framePointerReliable {
			return &sdtypes.UnwindInfoStop
		}
		return &sdtypes.UnwindInfoFramePointer
	case "runtime.sigreturn", "runtime.sigreturn__sigaction":
		// signal frame restorers
		return &sdtypes.UnwindInfoSignal
	}
	return nil
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

func resolveCUStrategies(r io.ReaderAt, g *Gopclntab,
	getSourceFileStrategy func(sourceFile string) strategy) map[int]strategy {

	rdr := pfbufio.GetReader()
	defer pfbufio.PutReader(rdr)

	// Walk all filenames and record the ones needing a strategy
	rdr.Init(r, g.headerOffset+int64(g.filetabOffset), int64(g.pctabOffset-g.filetabOffset))
	offsetStrategy := make(map[int]strategy)
	for range g.numFiles {
		offset := rdr.Tell()
		filename, err := rdr.ReadString(0)
		if err != nil {
			return nil
		}
		if s := getSourceFileStrategy(filename); s != strategyUnknown {
			offsetStrategy[int(offset)] = s
		}
	}

	// Walk cutab indexes and map tham to strategy
	rdr.Init(r, g.headerOffset+int64(g.cuOffset), int64(g.filetabOffset-g.cuOffset))
	cuStrategy := make(map[int]strategy)
	for idx := 0; true; idx++ {
		offsetBytes, err := rdr.ReadN(4)
		if err != nil {
			break
		}
		offset := int(binary.LittleEndian.Uint32(offsetBytes))
		if s, ok := offsetStrategy[offset]; ok {
			cuStrategy[int(idx)] = s
		}
	}

	return cuStrategy
}

func resolveFunctionUnwindInfo(r io.ReaderAt, g *Gopclntab, arch elf.Machine,
	framePointerReliable bool) map[int32]*sdtypes.UnwindInfo {

	rdr := pfbufio.GetReader()
	defer pfbufio.PutReader(rdr)

	functionInfo := make(map[int32]*sdtypes.UnwindInfo)

	rdr.Init(r, g.headerOffset+int64(g.funcnameOffset), int64(g.cuOffset-g.funcnameOffset))
	for {
		offset := rdr.Tell()
		funcName, err := rdr.ReadString(0)
		if err != nil {
			break
		}
		if info := getFunctionUnwindInfo(funcName, arch, framePointerReliable); info != nil {
			functionInfo[int32(offset)] = info
		}
	}
	return functionInfo
}

// Parse Golang .gopclntab spdelta tables and try to produce minified intervals
// by using large frame pointer ranges when possible
func (ee *elfExtractor) parseGoPclntab() error {
	g, err := NewGopclntab(ee.file)
	if errors.Is(err, errNoPclntab) {
		return nil
	}
	if err != nil {
		return err
	}
	defer g.Close()

	// Get target machine architecture for the ELF file
	arch := ee.file.Machine
	defaultStrategy := strategyFramePointer
	isFramePointerReliable := true
	var parsePclntab func(deltas *sdtypes.StackDeltaArray, p pcval, s strategy) error
	var cuStrategy map[int]strategy

	switch arch {
	case elf.EM_X86_64:
		parsePclntab = parseX86pclntabFunc
		// Go uses frame-pointers by default since Go 1.7, but unfortunately
		// it is not necessarily available when in code from non-Golang source
		// files, such as the assembly, of the Go runtime.
		// Since Golang binaries are huge statically compiled executables and
		// would fill up our precious kernel delta maps fast, the strategy is to
		// create deltastack maps for non-Go source files only, and otherwise
		// cover the vast majority with "use frame pointer" stack delta.
		cuStrategy = resolveCUStrategies(ee.file.Underlying(), g, getSourceFileStrategyX86)
	case elf.EM_AARCH64:
		parsePclntab = parseArm64pclntabFunc
		// Go 1.20 and earlier did not maintain frame pointers properly on arm64.
		// This was fixed for Go 1.21 and later in:
		// https://github.com/golang/go/commit/a41a29ad19c25c3475a65b7265fcad870d954c2a
		switch g.version {
		case go1_16, go1_18:
			// Magic indicates old Go with broken arm64 frame pointers
			defaultStrategy = strategyDeltasWithFrame
			isFramePointerReliable = false
		case go1_20:
			// Ambiguous regarding if frame pointer is kept correctly.
			// Take the slow path of resolving Go version.
			goVer, err := ee.file.GoVersion()
			if err != nil || version.Compare(goVer, "go1.21rc1") < 0 {
				defaultStrategy = strategyDeltasWithFrame
				isFramePointerReliable = false
			}
		}
	default:
		return fmt.Errorf("unsupported ELF architecture (%x)", arch)
	}

	funcUnwindInfo := resolveFunctionUnwindInfo(ee.file.Underlying(), g, arch, isFramePointerReliable)

	// Iterate the golang PC to function lookup table (sorted by PC)
	for i := 0; i < g.numFuncs; i++ {
		mapPc, funcOff := g.getFuncMapEntry(i)
		funcPc, fun := g.getFunc(funcOff)
		if fun == nil || mapPc != funcPc {
			return fmt.Errorf(".gopclntab func %v descriptor is invalid (pc %x/%x)",
				i, mapPc, funcPc)
		}

		// First, check for functions with special handling.
		if info, ok := funcUnwindInfo[int32(fun.nameOff)]; ok {
			ee.deltas.Add(sdtypes.StackDelta{
				Address: uint64(funcPc),
				Info:    *info,
			})
			continue
		}

		// Use source file to determine strategy if possible, and default
		// to using frame pointers in the unlikely case of no file info
		fileStrategy := defaultStrategy
		if fun.pcfileOff != 0 {
			p := g.getPcval(fun.pcfileOff, uint(funcPc))
			cuIndex := int(p.val) + int(fun.npcData)
			if s, ok := cuStrategy[cuIndex]; ok {
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
		if len(g.pctab) < int(fun.pcspOff) {
			return fmt.Errorf(".gopclntab func %v pcscOff (%d) is invalid",
				i, fun.pcspOff)
		}
		p := g.getPcval(fun.pcspOff, uint(funcPc))
		if err := parsePclntab(ee.deltas, p, fileStrategy); err != nil {
			return err
		}
	}

	// Filter out .gopclntab info from other sources
	start, _ := g.getFuncMapEntry(0)
	end, _ := g.getFuncMapEntry(g.numFuncs)
	ee.hooks.golangHook(start, end)

	// Add end of code indicator
	ee.deltas.Add(sdtypes.StackDelta{
		Address: uint64(end),
		Info:    sdtypes.UnwindInfoInvalid,
	})

	return nil
}
