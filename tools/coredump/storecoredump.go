// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
)

type StoreCoredump struct {
	*process.CoredumpProcess

	store     *modulestore.Store
	modules   map[string]ModuleInfo
	tempFiles map[string]string
}

var _ pfelf.ELFOpener = &StoreCoredump{}

func (scd *StoreCoredump) openFile(path string) (process.ReadAtCloser, error) {
	info, ok := scd.modules[path]
	if !ok {
		// The test case creator should have bundled everything.
		// However, old test cases have no bundle at all, so give a warning
		// only if some modules exists.
		if len(scd.modules) != 0 {
			log.Warnf("Store does not bundle %s", path)
		}
		return nil, fmt.Errorf("failed to open file `%s`: %w", path, os.ErrNotExist)
	}

	// The module is available from store.
	file, err := scd.store.OpenBufferedReadAt(info.Ref, 4*1024*1024)
	if err != nil {
		return nil, fmt.Errorf("failed to open file `%s`: %w", path, err)
	}
	return file, nil
}

func (scd *StoreCoredump) OpenMappingFile(m *process.RawMapping) (process.ReadAtCloser, error) {
	return scd.openFile(m.Path)
}

func (scd *StoreCoredump) OpenELF(path string) (*pfelf.File, error) {
	file, err := scd.openFile(path)
	if err == nil {
		return pfelf.NewFile(file, 0, false)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Fallback to the native CoredumpProcess
	return scd.CoredumpProcess.OpenELF(path)
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
	n, err := r.scd.CoredumpProcess.ReadAt(p, addr)
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
	file, openErr := r.scd.OpenMappingFile(&covering)
	if openErr != nil {
		return n, err
	}
	defer file.Close()
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
	coreELF, err := pfelf.NewFile(reader, 0, false)
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
