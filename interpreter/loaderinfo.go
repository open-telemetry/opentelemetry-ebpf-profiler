// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package interpreter // import "go.opentelemetry.io/ebpf-profiler/interpreter"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/util"
)

// LoaderInfo contains information about an ELF that is passed to
// the interpreter loaders.
type LoaderInfo struct {
	// fileID is the FileID of the ELF file.
	fileID host.FileID
	// elfRef provides a cached access to the ELF file.
	elfRef *pfelf.Reference
	// gaps represents holes in the stack deltas of the executable.
	gaps []util.Range
	// deltas contains the stack deltas for the executable.
	deltas sdtypes.StackDeltaArray
}

// NewLoaderInfo returns a populated LoaderInfo struct.
func NewLoaderInfo(fileID host.FileID, elfRef *pfelf.Reference, gaps []util.Range,
	deltas sdtypes.StackDeltaArray) *LoaderInfo {
	return &LoaderInfo{
		fileID: fileID,
		elfRef: elfRef,
		gaps:   gaps,
		deltas: deltas,
	}
}

// GetELF returns and caches a *pfelf.File for this LoaderInfo.
func (i *LoaderInfo) GetELF() (*pfelf.File, error) {
	return i.elfRef.GetELF()
}

// GetSymbolAsRanges returns the normalized virtual address ranges for the named symbol
func (i *LoaderInfo) GetSymbolAsRanges(symbol libpf.SymbolName) ([]util.Range, error) {
	ef, err := i.GetELF()
	if err != nil {
		return nil, err
	}
	sym, err := ef.LookupSymbol(symbol)
	if err != nil {
		return nil, fmt.Errorf("symbol '%v' not found: %w", symbol, err)
	}
	start := uint64(sym.Address)
	return []util.Range{{
		Start: start,
		End:   start + uint64(sym.Size)},
	}, nil
}

// FileID returns the fileID  element of the LoaderInfo struct.
func (i *LoaderInfo) FileID() host.FileID {
	return i.fileID
}

// FileName returns the fileName  element of the LoaderInfo struct.
func (i *LoaderInfo) FileName() string {
	return i.elfRef.FileName()
}

// Gaps returns the gaps for the executable of this LoaderInfo.
func (i *LoaderInfo) Gaps() []util.Range {
	return i.gaps
}

// Deltas returns and caches a *pfelf.File for this LoaderInfo.
func (i *LoaderInfo) Deltas() sdtypes.StackDeltaArray {
	return i.deltas
}
