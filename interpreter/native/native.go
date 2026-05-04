// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package native implements opt-in on-host symbolization of native frames
// using ELF symbol tables (.symtab/.dynsym). It is enabled via the "symtab"
// tracer type in IncludedTracers.
//
// This plugin loads function symbols into memory for all mapped native
// binaries. The memory overhead scales with the number and size of symbol
// tables on the host, so it should not be enabled by default in production
// without considering the memory budget.
package native // import "go.opentelemetry.io/ebpf-profiler/interpreter/native"

import (
	"fmt"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/ianlancetaylor/demangle"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/successfailurecounter"
)

var (
	_ interpreter.Data     = &nativeData{}
	_ interpreter.Instance = &nativeInstance{}
)

// symbolEntry represents a single function symbol with its address range.
type symbolEntry struct {
	address uint64
	end     uint64 // address + size
	name    libpf.String
}

// nativeData holds the parsed symbol table for a single ELF.
type nativeData struct {
	refs   atomic.Int32
	fileID host.FileID
	// symbols is sorted by address for binary search.
	symbols []symbolEntry
}

type nativeInstance struct {
	interpreter.InstanceStubs

	successCount atomic.Uint64
	failCount    atomic.Uint64

	d *nativeData
}

// Loader is the interpreter.Loader for native symbol resolution.
// It checks if the ELF has a .symtab section (directly or via .gnu_debuglink)
// and loads function symbols from it.
// Go binaries are skipped since they are handled by the Go-specific symbolizer.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Skip Go binaries — the Go symbolizer handles them. This means CGO
	// native symbols in Go binaries won't be resolved by this plugin.
	// A future improvement could filter to only non-Go symbols in such binaries.
	if ef.IsGolang() {
		return nil, nil
	}

	symbols := loadSymbols(ef, info.FileName())
	if len(symbols) == 0 {
		return nil, nil
	}

	sort.Slice(symbols, func(i, j int) bool {
		return symbols[i].address < symbols[j].address
	})

	d := &nativeData{
		fileID:  info.FileID(),
		symbols: symbols,
	}
	d.refs.Store(1)
	return d, nil
}

// loadSymbols extracts FUNC symbols from the ELF's .symtab, falling back to
// .dynsym, and if neither is present, trying the debug-linked ELF.
func loadSymbols(ef *pfelf.File, elfPath string) []symbolEntry {
	if syms := collectSymbols(ef.VisitSymbols); len(syms) > 0 {
		return syms
	}
	if syms := collectSymbols(ef.VisitDynamicSymbols); len(syms) > 0 {
		return syms
	}

	// Try debug-linked ELF.
	debugELF, _ := ef.OpenDebugLink(elfPath, pfelf.SystemOpener)
	if debugELF == nil {
		return nil
	}
	defer debugELF.Close()

	if syms := collectSymbols(debugELF.VisitSymbols); len(syms) > 0 {
		return syms
	}
	return collectSymbols(debugELF.VisitDynamicSymbols)
}

// demangleSymbol attempts to demangle C++ and Rust mangled symbol names.
// If the name is not mangled or demangling fails, it returns the original name.
func demangleSymbol(name string) string {
	if strings.HasPrefix(name, "_Z") || strings.HasPrefix(name, "_R") {
		if demangled, err := demangle.ToString(name); err == nil {
			return demangled
		}
	}
	return name
}

// collectSymbols visits a symbol table and returns entries for symbols with
// nonzero addresses and sizes.
func collectSymbols(visit func(func(libpf.Symbol) bool) error) []symbolEntry {
	var symbols []symbolEntry

	err := visit(func(sym libpf.Symbol) bool {
		if sym.Address == 0 || sym.Size == 0 || !sym.Type.IsFunction() {
			return true
		}
		name := string(sym.Name)
		if name == "" {
			return true
		}
		name = demangleSymbol(name)
		symbols = append(symbols, symbolEntry{
			address: uint64(sym.Address),
			end:     uint64(sym.Address) + sym.Size,
			name:    libpf.Intern(name),
		})
		return true
	})
	if err != nil {
		return nil
	}
	return symbols
}

// lookupSymbol performs a binary search to find the function containing addr.
func (d *nativeData) lookupSymbol(addr uint64) (libpf.String, bool) {
	i := sort.Search(len(d.symbols), func(i int) bool {
		return d.symbols[i].address > addr
	}) - 1

	if i < 0 {
		return libpf.NullString, false
	}
	sym := &d.symbols[i]
	if addr >= sym.address && addr < sym.end {
		return sym.name, true
	}
	return libpf.NullString, false
}

func (d *nativeData) unref() {
	d.refs.Add(-1)
}

func (d *nativeData) String() string {
	return fmt.Sprintf("Native symbolizer (%d symbols)", len(d.symbols))
}

func (d *nativeData) Attach(_ interpreter.EbpfHandler, _ libpf.PID,
	_ libpf.Address, _ remotememory.RemoteMemory) (interpreter.Instance, error) {
	d.refs.Add(1)
	return &nativeInstance{d: d}, nil
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
	name, ok := inst.d.lookupSymbol(address)
	if !ok {
		return fmt.Errorf("no symbol for 0x%x", address)
	}

	if ef.Flags().ReturnAddress() {
		address--
	}
	frames.Append(&libpf.Frame{
		Type:            ef.Type(),
		AddressOrLineno: libpf.AddressOrLineno(address),
		Mapping:         mapping,
		FunctionName:    name,
	})
	sfCounter.ReportSuccess()
	return nil
}

func (inst *nativeInstance) ReleaseResources() error {
	return nil
}
