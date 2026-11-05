// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package native names native frames from ELF symbol tables. It is off by
// default since the symbol tables cost memory per executable.
package native // import "go.opentelemetry.io/ebpf-profiler/interpreter/native"

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"
	"io/fs"
	"math"
	"sort"
	"strings"
	"sync/atomic"

	lru "github.com/elastic/go-freelru"
	"github.com/ianlancetaylor/demangle"
	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
)

var (
	_ interpreter.Data     = &nativeData{}
	_ interpreter.Instance = &nativeInstance{}
)

const maxNesting = 8 // nested and aliased symbols checked per lookup

type symbolEntry struct {
	address uint32
	size    uint32
	nameOff uint32
}

type nativeData struct {
	fileID host.FileID
	// Keyed by the top 32 bits of the address, each bucket sorted by the rest.
	symbols map[uint32][]symbolEntry
	numSyms int
	// Names come from strtab for .symtab, or from process memory at dynstrAddr.
	strtab     []byte
	dynstrAddr uint64
	nameCache  *lru.SyncedLRU[uint32, string]
	dataRef    io.Closer
	refs       atomic.Int32
}

type nativeInstance struct {
	interpreter.InstanceStubs

	successCount atomic.Uint64
	failCount    atomic.Uint64

	d    *nativeData
	rm   remotememory.RemoteMemory
	bias libpf.Address
}

// GetLoader returns the interpreter.Loader for native symbol resolution.
func GetLoader(cfg Config) interpreter.Loader {
	return interpreter.NewLoader(
		func(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
			return load(cfg, info)
		}, nil)
}

func load(cfg Config, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Go has its own symbolizer. This misses CGO functions for now.
	if ef.IsGolang() {
		return nil, nil
	}

	symbols, strtab, dynstrAddr, dataRef := loadSymbols(ef, info.FileName(), info.FS())
	if len(symbols) == 0 {
		return nil, nil
	}
	numSyms := countSymbols(symbols)
	if cfg.MaxSymbols != 0 && numSyms > int(cfg.MaxSymbols) {
		log.Debugf("file %s has %d function symbols, over max_symbols %d, skipping",
			info.FileName(), numSyms, cfg.MaxSymbols)
		_ = dataRef.Close()
		return nil, nil
	}

	nameCache, err := lru.NewSynced[uint32, string](cfg.nameCacheSize(), hash.Uint32)
	if err != nil {
		_ = dataRef.Close()
		return nil, fmt.Errorf("failed to create name cache: %w", err)
	}

	d := &nativeData{
		fileID:     info.FileID(),
		symbols:    symbols,
		numSyms:    numSyms,
		strtab:     strtab,
		dynstrAddr: dynstrAddr,
		nameCache:  nameCache,
		dataRef:    dataRef,
	}
	d.refs.Store(1)
	return d, nil
}

// loadSymbols tries .symtab, then the debug ELF's .symtab, then .dynsym.
func loadSymbols(ef *pfelf.File, elfPath string, fsys fs.FS) (
	map[uint32][]symbolEntry, []byte, uint64, io.Closer) {
	if syms, strtab, _ := collectSymbolOffsets(ef, ".symtab"); len(syms) > 0 {
		return syms, strtab, 0, ef.Take()
	}

	if debugELF, _ := ef.OpenDebugLink(elfPath, fsys); debugELF != nil {
		if syms, strtab, _ := collectSymbolOffsets(debugELF, ".symtab"); len(syms) > 0 {
			return syms, strtab, 0, debugELF
		}
		_ = debugELF.Close()
	}

	if syms, _, dynstr := collectSymbolOffsets(ef, ".dynsym"); len(syms) > 0 &&
		dynstr.Flags&elf.SHF_ALLOC != 0 && dynstr.Addr != 0 {
		return syms, nil, dynstr.Addr, pfelf.NoMmapCloser{}
	}
	return nil, nil, 0, nil
}

func collectSymbolOffsets(ef *pfelf.File, sectionName string) (
	map[uint32][]symbolEntry, []byte, *pfelf.Section) {
	symTab := ef.Section(sectionName)
	if symTab == nil {
		return nil, nil, nil
	}

	if symTab.Link == 0 || symTab.Link >= uint32(len(ef.Sections)) {
		return nil, nil, nil
	}

	strTab := &ef.Sections[symTab.Link]
	strtab, err := strTab.Data(16 * 1024 * 1024)
	if err != nil {
		return nil, nil, nil
	}

	rdr := pfbufio.NewReader(symTab, 0, int64(symTab.FileSize))
	defer rdr.Release()

	sym := &elf.Sym64{}
	symbols := make(map[uint32][]symbolEntry)

	for {
		if _, err := io.ReadFull(&rdr, pfunsafe.FromPointer(sym)); err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				break
			}
			return nil, nil, nil
		}
		t := elf.ST_TYPE(sym.Info)
		if t != elf.STT_FUNC && t != elf.STT_GNU_IFUNC || sym.Value == 0 || sym.Size == 0 ||
			sym.Size > math.MaxUint32 || int(sym.Name) >= len(strtab) || strtab[sym.Name] == 0 {
			continue
		}
		high := uint32(sym.Value >> 32)
		symbols[high] = append(symbols[high], symbolEntry{
			address: uint32(sym.Value),
			size:    uint32(sym.Size),
			nameOff: sym.Name,
		})
	}
	if len(symbols) == 0 {
		return nil, nil, nil
	}
	for high := range symbols {
		sort.Slice(symbols[high], func(i, j int) bool {
			return symbols[high][i].address < symbols[high][j].address
		})
	}
	return symbols, strtab, strTab
}

func demangleSymbol(name string) string {
	if strings.HasPrefix(name, "_Z") || strings.HasPrefix(name, "_R") {
		if demangled, err := demangle.ToString(name); err == nil {
			return demangled
		}
	}
	return name
}

func (inst *nativeInstance) symbolName(nameOff uint32) string {
	d := inst.d
	if name, ok := d.nameCache.Get(nameOff); ok {
		return name
	}

	var raw string
	if d.strtab != nil {
		if end := bytes.IndexByte(d.strtab[nameOff:], 0); end >= 0 {
			raw = string(d.strtab[nameOff : int(nameOff)+end])
		}
	} else {
		raw = inst.rm.String(inst.bias + libpf.Address(d.dynstrAddr+uint64(nameOff)))
	}
	if raw == "" {
		return ""
	}
	name := demangleSymbol(raw)
	d.nameCache.Add(nameOff, name)
	return name
}

func (d *nativeData) lookupSymbol(addr uint64) (uint32, bool) {
	symbols := d.symbols[uint32(addr>>32)]
	lowAddr := uint32(addr)
	i := sort.Search(len(symbols), func(i int) bool {
		return symbols[i].address > lowAddr
	}) - 1

	for j := i; j >= 0 && j > i-maxNesting; j-- {
		if sym := &symbols[j]; lowAddr-sym.address < sym.size {
			return sym.nameOff, true
		}
	}
	return 0, false
}

func (d *nativeData) String() string {
	return fmt.Sprintf("Native symbolizer (%d symbols)", d.numSyms)
}

func countSymbols(symbols map[uint32][]symbolEntry) int {
	count := 0
	for _, bucket := range symbols {
		count += len(bucket)
	}
	return count
}

func (d *nativeData) unref() {
	if d.refs.Add(-1) == 0 {
		_ = d.dataRef.Close()
	}
}

func (d *nativeData) Attach(_ interpreter.EbpfHandler, _ libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory) (interpreter.Instance, error) {
	d.refs.Add(1)
	return &nativeInstance{d: d, rm: rm, bias: bias}, nil
}

func (d *nativeData) Unload(_ interpreter.EbpfHandler) {
	d.unref()
}

func (inst *nativeInstance) GetAndResetMetrics() ([]metrics.Metric, error) {
	return []metrics.Metric{
		{
			ID:    metrics.IDNativeSymbolizationSuccess,
			Value: metrics.MetricValue(inst.successCount.Swap(0)),
		},
		{
			ID:    metrics.IDNativeSymbolizationFailure,
			Value: metrics.MetricValue(inst.failCount.Swap(0)),
		},
	}, nil
}

func (inst *nativeInstance) Detach(_ interpreter.EbpfHandler, _ libpf.PID) error {
	inst.d.unref()
	return nil
}

func (inst *nativeInstance) Symbolize(ef libpf.EbpfFrame, frames *libpf.Frames,
	mapping libpf.FrameMapping) error {
	if !ef.Type().IsInterpType(libpf.Native) {
		return interpreter.ErrMismatchInterpreterType
	}
	if host.FileID(ef.Variable(0)) != inst.d.fileID {
		return interpreter.ErrMismatchInterpreterType
	}

	sfCounter := successfailurecounter.New(&inst.successCount, &inst.failCount)
	defer sfCounter.DefaultToFailure()

	address := ef.Data()
	// See comment about return address handling in ProcessManager.convertFrame
	if ef.Flags().ReturnAddress() {
		address--
	}
	nameOff, ok := inst.d.lookupSymbol(address)
	if !ok {
		return fmt.Errorf("no symbol for 0x%x", address)
	}
	name := inst.symbolName(nameOff)
	if name == "" {
		return fmt.Errorf("unreadable symbol name for 0x%x", address)
	}
	frames.Append(&libpf.Frame{
		Type:            ef.Type(),
		AddressOrLineno: libpf.AddressOrLineno(address),
		Mapping:         mapping,
		FunctionName:    libpf.Intern(name),
	})
	sfCounter.ReportSuccess()
	return nil
}
