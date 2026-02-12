// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oomwatcher // import "go.opentelemetry.io/ebpf-profiler/interpreter/oomwatcher"

import (
	"errors"
	"fmt"

	"github.com/parca-dev/oomprof/oomprof"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// pfelfReader implements oomprof.ELFReader using libpf/pfelf.
type pfelfReader struct{}

// Open opens an ELF file using pfelf.
func (r *pfelfReader) Open(path string) (oomprof.ELFFile, error) {
	file, err := pfelf.Open(path)
	if err != nil {
		return nil, err
	}
	return &pfelfFile{file: file}, nil
}

// pfelfFile implements oomprof.ELFFile using libpf/pfelf.File.
type pfelfFile struct {
	file *pfelf.File
}

// Close closes the ELF file.
func (f *pfelfFile) Close() error {
	return f.file.Close()
}

// GetBuildID returns the build ID of the ELF file.
func (f *pfelfFile) GetBuildID() (string, error) {
	return f.file.GetBuildID()
}

// GoVersion returns the Go version the binary was built with.
func (f *pfelfFile) GoVersion() (string, error) {
	return f.file.GoVersion()
}

// LookupSymbol looks up a symbol by name and returns its address.
func (f *pfelfFile) LookupSymbol(name string) (oomprof.SymbolInfo, error) {
	sym, err := f.file.LookupSymbol(libpf.SymbolName(name))
	if err != nil {
		if errors.Is(err, libpf.ErrSymbolNotFound) {
			return oomprof.SymbolInfo{}, fmt.Errorf("symbol %s not found", name)
		}
		return oomprof.SymbolInfo{}, err
	}

	return oomprof.SymbolInfo{
		Name:    string(sym.Name),
		Address: uint64(sym.Address),
	}, nil
}
