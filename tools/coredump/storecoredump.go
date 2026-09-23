// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"io/fs"
	"os"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

type StoreCoredump struct {
	*process.CoredumpProcess

	store     *modulestore.Store
	modules   map[string]ModuleInfo
	tempFiles map[string]string
}

var _ fs.FS = &StoreCoredump{}

// Open implements the fs.FS interface. It prefers content from the module
// store (which holds the original, unmodified on-disk files bundled with the
// test case), falling back to the coredump's own partial data for name.
func (scd *StoreCoredump) Open(name string) (fs.File, error) {
	info, ok := scd.modules[name]
	if !ok {
		// Bundle miss: fall back to whatever partial data the coredump
		// itself carries for legacy test cases without bundled modules.
		return scd.CoredumpProcess.Open(name)
	}

	// The module is available from store.
	file, err := scd.store.OpenBufferedReadAt(info.Ref, 4*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("failed to open file `%s`: %w", name, err)
	}
	return process.NewFile(file), nil
}

// remoteReaderWithModuleFallback satisfies io.ReaderAt by first trying the
// coredump's own PT_LOAD segments and, on a miss, falling back to reading the
// corresponding file offset from the bundled module file. The kernel omits
// read-only file-backed mappings from coredumps by default; without the
// fallback, virtual addresses that land in such regions (e.g. the metadata
// pages of .NET 10 R2R DLLs) would read as zeros and break interpreters that
// expect to find the file content in process memory.
type remoteReaderWithModuleFallback struct {
	scd *StoreCoredump
}

func (r *remoteReaderWithModuleFallback) ReadAt(p []byte, addr int64) (int, error) {
	n, err := r.scd.ReadAt(p, addr)
	if err == nil {
		return n, nil
	}
	// Locate the file-backed mapping covering this virtual address, if any.
	var covering process.RawMapping
	var found bool
	_, _ = r.scd.IterateMappings(func(m process.RawMapping) bool {
		if uint64(addr) >= m.Vaddr && uint64(addr) < m.Vaddr+m.Length {
			covering = m
			found = true
			return false
		}
		return true
	})
	if !found {
		return n, err
	}
	f, openErr := process.OpenMapping(r.scd, &covering)
	if openErr != nil {
		return n, err
	}
	defer f.Close()
	file, ok := f.(io.ReaderAt)
	if !ok {
		return n, err
	}
	fileOff := covering.FileOffset + (uint64(addr) - covering.Vaddr)
	return file.ReadAt(p, int64(fileOff))
}

func (scd *StoreCoredump) GetRemoteMemory() remotememory.RemoteMemory {
	base := scd.CoredumpProcess.GetRemoteMemory()
	return remotememory.RemoteMemory{
		ReaderAt: &remoteReaderWithModuleFallback{scd: scd},
		Bias:     base.Bias,
	}
}

func (scd *StoreCoredump) Close() error {
	for _, tmpFile := range scd.tempFiles {
		_ = os.Remove(tmpFile)
	}
	return scd.CoredumpProcess.Close()
}

func OpenStoreCoredump(store *modulestore.Store, coreFileRef modulestore.ID, modules []ModuleInfo) (
	process.Process, error,
) {
	// Open the coredump from the module store.
	reader, err := store.OpenBufferedReadAt(coreFileRef, 16*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("failed to open coredump file reader: %w", err)
	}
	coreELF, err := pfelf.NewFileOwned(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to open coredump ELF: %w", err)
	}
	core, err := process.OpenCoredumpFile(coreELF)
	if err != nil {
		return nil, fmt.Errorf("failed to open coredump: %w", err)
	}

	moduleMap := map[string]ModuleInfo{}
	for _, module := range modules {
		moduleMap[module.LocalPath] = module
	}

	return &StoreCoredump{
		CoredumpProcess: core,

		store:     store,
		modules:   moduleMap,
		tempFiles: make(map[string]string),
	}, nil
}
