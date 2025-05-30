// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// This implements Go 1.2+ .pclntab symbol parsing as defined
// in http://golang.org/s/go12symtab. The Golang runtime implementation of
// this is in go/src/runtime/symtab.go, but unfortunately it is not exported.

package elfunwindinfo // import "go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"

import (
	"bytes"
	"debug/elf"
	"fmt"
	"go/version"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
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
	"runtime.sigreturn": &sdtypes.UnwindInfoSignal,
}

const (
	// maximum pclntab (or rodata segment) size to inspect. The .gopclntab is
	// often huge. Host agent binaries have about 32M .rodata, so allow for more.
	maxBytesGoPclntab = 128 * 1024 * 1024

	// pclntabHeader magic identifying Go version
	magicGo1_2  = 0xfffffffb
	magicGo1_16 = 0xfffffffa
	magicGo1_18 = 0xfffffff0
	magicGo1_20 = 0xfffffff1
)

// pclntabHeader is the Golang pclntab header structure
//
//nolint:structcheck
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
//
//nolint:structcheck
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
//
//nolint:structcheck
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
//
//nolint:structcheck
type pclntabFuncMap struct {
	pc      uint64
	funcOff uint64
}

// pclntabFunc is the Golang function definition (struct _func in the spec) as before Go 1.18.
//
//nolint:structcheck
type pclntabFunc struct {
	startPc                      uint64
	nameOff, argsSize, frameSize int32
	pcspOff, pcfileOff, pclnOff  int32
	nfuncData, npcData           int32
}

// pclntabFunc118 is the Golang function definition (struct _func in the spec)
// starting with Go 1.18.
// see: go/src/runtime/runtime2.go (struct _func)
//
//nolint:structcheck
type pclntabFunc118 struct {
	entryoff                     uint32 // start pc, as offset from pcHeader.textStart
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

// IsGo118orNewer returns true if magic matches with the Go 1.18 or newer.
func IsGo118orNewer(magic uint32) bool {
	return magic == magicGo1_18 || magic == magicGo1_20
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

// getString returns a zero terminated string from the data slice at given offset as []byte
func getString(data []byte, offset int) []byte {
	if offset < 0 || offset > len(data) {
		return nil
	}
	zeroIdx := bytes.IndexByte(data[offset:], 0)
	if zeroIdx < 0 {
		return nil
	}
	return data[offset : offset+zeroIdx]
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
var noFPSourceSuffixes = [][]byte{
	[]byte("/src/crypto/sha1/sha1.go"),
	[]byte("/src/crypto/sha256/sha256.go"),
	[]byte("/src/crypto/sha512/sha512.go"),
	[]byte("/src/crypto/elliptic/p256_asm.go"),
	[]byte("golang.org/x/crypto/curve25519/curve25519_amd64.go"),
	[]byte("golang.org/x/crypto/chacha20poly1305/chacha20poly1305_amd64.go"),
}

// getSourceFileStrategy categorizes sourceFile's unwinding strategy based on its name
func getSourceFileStrategy(arch elf.Machine, sourceFile []byte, defaultStrategy strategy) strategy {
	switch arch {
	case elf.EM_X86_64:
		// Most of the assembly code needs explicit SP delta as they do not
		// create stack frame. Do not recover RBP as it is not modified.
		if bytes.HasSuffix(sourceFile, []byte(".s")) {
			return strategyDeltasWithoutFrame
		}
		// Check for the Go source files needing SP delta unwinding to recover RBP
		for _, suffix := range noFPSourceSuffixes {
			if bytes.HasSuffix(sourceFile, suffix) {
				return strategyDeltasWithFrame
			}
		}
		return defaultStrategy
	default:
		return defaultStrategy
	}
}

// SearchGoPclntab uses heuristic to find the gopclntab from RO data.
func SearchGoPclntab(ef *pfelf.File) ([]byte, error) {
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

		var data []byte
		var err error
		if data, err = p.Data(maxBytesGoPclntab); err != nil {
			return nil, err
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
			switch hdr.magic {
			case magicGo1_20, magicGo1_18, magicGo1_16, magicGo1_2:
				return data[i:], nil
			}
		}
	}

	for i := range ef.Sections {
		s := &ef.Sections[i]
		if s.Name != ".gopclntab" {
			continue
		}
		return s.Data(maxBytesGoPclntab)
	}

	return nil, nil
}

// Parse Golang .gopclntab spdelta tables and try to produce minified intervals
// by using large frame pointer ranges when possible
func (ee *elfExtractor) parseGoPclntab() error {
	var err error
	var data []byte

	ef := ee.file

	if ef.InsideCore {
		// Section tables not available. Use heuristic. Ignore errors as
		// this might not be a Go binary.
		data, _ = SearchGoPclntab(ef)
	} else if s := ef.Section(".gopclntab"); s != nil {
		// Load the .gopclntab via section if available.
		if data, err = s.Data(maxBytesGoPclntab); err != nil {
			return fmt.Errorf("failed to load .gopclntab section: %v", err)
		}
	} else if s := ef.Section(".go.buildinfo"); s != nil {
		// This looks like Go binary. Lookup the runtime.pclntab symbols,
		// as the .gopclntab section is not available on PIE binaries.
		// A full symbol table read is needed as these are not dynamic symbols.
		// Consequently these symbols might be unavailable on a stripped binary.
		symtab, err := ef.ReadSymbols()
		if err != nil {
			// It seems the Go binary was stripped. So we use the heuristic approach
			// to get the stack deltas.
			if data, err = SearchGoPclntab(ef); err != nil {
				return fmt.Errorf("failed to search .gopclntab: %v", err)
			}
		} else {
			start, err := symtab.LookupSymbolAddress("runtime.pclntab")
			if err != nil {
				return fmt.Errorf("failed to load .gopclntab via symbols: %v", err)
			}
			end, err := symtab.LookupSymbolAddress("runtime.epclntab")
			if err != nil {
				return fmt.Errorf("failed to load .gopclntab via symbols: %v", err)
			}
			if start >= end {
				return fmt.Errorf("invalid .gopclntab symbols: %v-%v", start, end)
			}
			data = make([]byte, end-start)
			if _, err := ef.ReadVirtualMemory(data, int64(start)); err != nil {
				return fmt.Errorf("failed to load .gopclntab via symbols: %v", err)
			}
		}
	}
	if data == nil {
		return nil
	}

	var textStart uintptr
	hdrSize := uintptr(PclntabHeaderSize())
	mapSize := unsafe.Sizeof(pclntabFuncMap{})
	funSize := unsafe.Sizeof(pclntabFunc{})
	dataLen := uintptr(len(data))
	if dataLen < hdrSize {
		return fmt.Errorf(".gopclntab is too short (%v)", len(data))
	}

	var functab, funcdata, funcnametab, filetab, pctab, cutab []byte

	hdr := (*pclntabHeader)(unsafe.Pointer(&data[0]))
	fieldSize := uintptr(hdr.ptrSize)
	switch hdr.magic {
	case magicGo1_2:
		functabEnd := int(hdrSize + uintptr(hdr.numFuncs)*mapSize + uintptr(hdr.ptrSize))
		filetabOffset := getInt32(data, functabEnd)
		numSourceFiles := getInt32(data, filetabOffset)
		if filetabOffset == 0 || numSourceFiles == 0 {
			return fmt.Errorf(".gopclntab corrupt (filetab 0x%x, nfiles %d)",
				filetabOffset, numSourceFiles)
		}
		functab = data[hdrSize:filetabOffset]
		cutab = data[filetabOffset:]
		pctab = data
		funcnametab = data
		funcdata = data
		filetab = data
	case magicGo1_16:
		hdrSize = unsafe.Sizeof(pclntabHeader116{})
		if dataLen < hdrSize {
			return fmt.Errorf(".gopclntab is too short (%v)", len(data))
		}
		hdr116 := (*pclntabHeader116)(unsafe.Pointer(&data[0]))
		if dataLen < hdr116.funcnameOffset || dataLen < hdr116.cuOffset ||
			dataLen < hdr116.filetabOffset || dataLen < hdr116.pctabOffset ||
			dataLen < hdr116.pclnOffset {
			return fmt.Errorf(".gopclntab is corrupt (%x, %x, %x, %x, %x)",
				hdr116.funcnameOffset, hdr116.cuOffset,
				hdr116.filetabOffset, hdr116.pctabOffset,
				hdr116.pclnOffset)
		}
		funcnametab = data[hdr116.funcnameOffset:]
		cutab = data[hdr116.cuOffset:]
		filetab = data[hdr116.filetabOffset:]
		pctab = data[hdr116.pctabOffset:]
		functab = data[hdr116.pclnOffset:]
		funcdata = functab
	case magicGo1_18, magicGo1_20:
		hdrSize = unsafe.Sizeof(pclntabHeader118{})
		if dataLen < hdrSize {
			return fmt.Errorf(".gopclntab is too short (%v)", dataLen)
		}
		hdr118 := (*pclntabHeader118)(unsafe.Pointer(&data[0]))
		if dataLen < hdr118.funcnameOffset || dataLen < hdr118.cuOffset ||
			dataLen < hdr118.filetabOffset || dataLen < hdr118.pctabOffset ||
			dataLen < hdr118.pclnOffset {
			return fmt.Errorf(".gopclntab is corrupt (%x, %x, %x, %x, %x)",
				hdr118.funcnameOffset, hdr118.cuOffset,
				hdr118.filetabOffset, hdr118.pctabOffset,
				hdr118.pclnOffset)
		}
		funcnametab = data[hdr118.funcnameOffset:]
		cutab = data[hdr118.cuOffset:]
		filetab = data[hdr118.filetabOffset:]
		pctab = data[hdr118.pctabOffset:]
		functab = data[hdr118.pclnOffset:]
		funcdata = functab
		textStart = hdr118.textStart
		funSize = unsafe.Sizeof(pclntabFunc118{})
		// With the change of the type of the first field of _func in Go 1.18, this
		// value is now hard coded.
		//
		//nolint:lll
		// See https://github.com/golang/go/blob/6df0957060b1315db4fd6a359eefc3ee92fcc198/src/debug/gosym/pclntab.go#L376-L382
		fieldSize = uintptr(4)
		mapSize = fieldSize * 2
	default:
		return fmt.Errorf(".gopclntab format (0x%x) not supported", hdr.magic)
	}
	if hdr.pad != 0 || hdr.ptrSize != 8 {
		return fmt.Errorf(".gopclntab header: %x, %x", hdr.pad, hdr.ptrSize)
	}

	// Go uses frame-pointers by default since Go 1.7, but unfortunately
	// it is not necessarily available when in code from non-Golang source
	// files, such as the assembly, of the Go runtime.
	// Since Golang binaries are huge statically compiled executables and
	// would fill up our precious kernel delta maps fast, the strategy is to
	// create deltastack maps for non-Go source files only, and otherwise
	// cover the vast majority with "use frame pointer" stack delta.
	sourceStrategy := make(map[int]strategy)

	// Get target machine architecture for the ELF file
	arch := ef.Machine
	defaultStrategy := strategyFramePointer
	var parsePclntab func(*sdtypes.StackDeltaArray, *pclntabFunc, uintptr, []byte,
		strategy, uint64, uint8) error

	switch arch {
	case elf.EM_X86_64:
		parsePclntab = parseX86pclntabFunc
	case elf.EM_AARCH64:
		parsePclntab = parseArm64pclntabFunc
		// Go 1.20 and earlier did not maintain frame pointers properly on arm64.
		// This was fixed for Go 1.21 and later in:
		// https://github.com/golang/go/commit/a41a29ad19c25c3475a65b7265fcad870d954c2a
		switch hdr.magic {
		case magicGo1_2, magicGo1_16, magicGo1_18:
			// Magic indicates old Go with broken arm64 frame pointers
			defaultStrategy = strategyDeltasWithFrame
		case magicGo1_20:
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

	fmap := &pclntabFuncMap{}
	fun := &pclntabFunc{}
	// Iterate the golang PC to function lookup table (sorted by PC)
	for i := uint64(0); i < hdr.numFuncs; i++ {
		if IsGo118orNewer(hdr.magic) {
			//nolint:lll
			// See: https://github.com/golang/go/blob/6df0957060b1315db4fd6a359eefc3ee92fcc198/src/debug/gosym/pclntab.go#L401-L413
			*fmap = pclntabFuncMap{}
			funcIdx := uintptr(i) * 2 * fieldSize
			fmap.pc = uint64(*(*uint32)(unsafe.Pointer(&functab[funcIdx])))
			fmap.funcOff = uint64(*(*uint32)(unsafe.Pointer(&functab[funcIdx+fieldSize])))
			fmap.pc += uint64(textStart)
		} else {
			fmap = (*pclntabFuncMap)(unsafe.Pointer(&functab[uintptr(i)*mapSize]))
		}
		// Get the function data
		if uintptr(len(funcdata)) < uintptr(fmap.funcOff)+funSize {
			return fmt.Errorf(".gopclntab func %v descriptor is invalid", i)
		}
		if IsGo118orNewer(hdr.magic) {
			tmp := (*pclntabFunc118)(unsafe.Pointer(&funcdata[fmap.funcOff]))
			*fun = pclntabFunc{
				startPc:   uint64(textStart) + uint64(tmp.entryoff),
				nameOff:   tmp.nameOff,
				argsSize:  tmp.argsSize,
				frameSize: tmp.argsSize,
				pcspOff:   tmp.pcspOff,
				pcfileOff: tmp.pcfileOff,
				pclnOff:   tmp.pclnOff,
				nfuncData: tmp.nfuncData,
				npcData:   tmp.npcData,
			}
		} else {
			fun = (*pclntabFunc)(unsafe.Pointer(&funcdata[fmap.funcOff]))
		}
		// First, check for functions with special handling.
		funcName := getString(funcnametab, int(fun.nameOff))
		if info, found := goFunctionsStopDelta[string(funcName)]; found {
			ee.deltas.Add(sdtypes.StackDelta{
				Address: fun.startPc,
				Info:    *info,
			})
			continue
		}

		// Use source file to determine strategy if possible, and default
		// to using frame pointers in the unlikely case of no file info
		fileStrategy := defaultStrategy
		if fun.pcfileOff != 0 {
			p := newPcval(pctab[fun.pcfileOff:], uint(fun.startPc), hdr.quantum)
			fileIndex := int(p.val)
			if hdr.magic == magicGo1_16 || IsGo118orNewer(hdr.magic) {
				fileIndex += int(fun.npcData)
			}

			// Determine strategy
			fileStrategy = sourceStrategy[fileIndex]
			if fileStrategy == strategyUnknown {
				sourceFile := getString(filetab, getInt32(cutab, 4*fileIndex))
				fileStrategy = getSourceFileStrategy(arch, sourceFile, defaultStrategy)
				sourceStrategy[fileIndex] = fileStrategy
			}
		}

		if fileStrategy == strategyFramePointer {
			// Use stack frame-pointer delta
			ee.deltas.Add(sdtypes.StackDelta{
				Address: fun.startPc,
				Info:    sdtypes.UnwindInfoFramePointer,
			})
			continue
		}
		if err := parsePclntab(ee.deltas, fun, dataLen, pctab, fileStrategy, i,
			hdr.quantum); err != nil {
			return err
		}
	}

	// Filter out .gopclntab info from other sources
	var start, end uintptr
	if IsGo118orNewer(hdr.magic) {
		//nolint:lll
		// https://github.com/golang/go/blob/6df0957060b1315db4fd6a359eefc3ee92fcc198/src/debug/gosym/pclntab.go#L440-L450
		start = uintptr(*(*uint32)(unsafe.Pointer(&functab[0])))
		start += textStart
		// From go12symtab document, reason for indexing beyond hdr.numFuncs:
		// "The final pcN value is the address just beyond func(N-1), so that the binary
		// search can distinguish between a pc inside func(N-1) and a pc outside the text
		// segment."
		end = uintptr(*(*uint32)(unsafe.Pointer(&functab[uintptr(hdr.numFuncs)*mapSize])))
		end += textStart
	} else {
		start = *(*uintptr)(unsafe.Pointer(&functab[0]))
		end = *(*uintptr)(unsafe.Pointer(&functab[uintptr(hdr.numFuncs)*mapSize]))
	}
	ee.hooks.golangHook(start, end)

	// Add end of code indicator
	ee.deltas.Add(sdtypes.StackDelta{
		Address: uint64(end),
		Info:    sdtypes.UnwindInfoInvalid,
	})

	return nil
}

// parseX86pclntabFunc extracts interval information from x86_64 based pclntabFunc.
func parseX86pclntabFunc(deltas *sdtypes.StackDeltaArray, fun *pclntabFunc, dataLen uintptr,
	pctab []byte, s strategy, i uint64, quantum uint8) error {
	if fun.pcspOff == 0 {
		// Some functions don't have PCSP info: skip them.
		return nil
	}
	// Generate stack deltas as the information is available
	if dataLen < uintptr(fun.pcspOff) {
		return fmt.Errorf(".gopclntab func %v pcscOff (%d) is invalid",
			i, fun.pcspOff)
	}

	p := newPcval(pctab[fun.pcspOff:], uint(fun.startPc), quantum)
	hints := sdtypes.UnwindHintKeep
	for ok := true; ok; ok = p.step() {
		info := sdtypes.UnwindInfo{
			Opcode: support.UnwindOpcodeBaseSP,
			Param:  p.val + 8,
		}
		if s == strategyDeltasWithFrame && info.Param >= 16 {
			info.FPOpcode = support.UnwindOpcodeBaseCFA
			info.FPParam = -16
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
func parseArm64pclntabFunc(deltas *sdtypes.StackDeltaArray, fun *pclntabFunc,
	dataLen uintptr, pctab []byte, s strategy, i uint64, quantum uint8) error {
	if fun.pcspOff == 0 {
		// Some CGO functions don't have PCSP info: skip them.
		return nil
	}
	if dataLen < uintptr(fun.pcspOff) {
		return fmt.Errorf(".gopclntab func %v pcspOff = %d is invalid", i, fun.pcspOff)
	}

	hint := sdtypes.UnwindHintKeep
	p := newPcval(pctab[fun.pcspOff:], uint(fun.startPc), quantum)
	for ok := true; ok; ok = p.step() {
		var info sdtypes.UnwindInfo
		if p.val == 0 {
			// Return instruction, function prologue or leaf function body: unwind via LR.
			info = sdtypes.UnwindInfoLR
		} else {
			// Regular basic block in the function body: unwind via SP.
			info = sdtypes.UnwindInfo{
				// Unwind via SP offset.
				Opcode: support.UnwindOpcodeBaseSP,
				Param:  p.val,
			}
			if s == strategyDeltasWithFrame {
				// On ARM64, the previous LR value is stored to top-of-stack.
				info.FPOpcode = support.UnwindOpcodeBaseSP
				info.FPParam = 0
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
