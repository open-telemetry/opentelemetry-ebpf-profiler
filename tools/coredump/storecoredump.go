// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/pfelf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/process"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/tools/coredump/modulestore"

	log "github.com/sirupsen/logrus"
)

type StoreCoredump struct {
	*process.CoredumpProcess

	store   *modulestore.Store
	modules map[string]ModuleInfo
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

func (scd *StoreCoredump) OpenMappingFile(m *process.Mapping) (process.ReadAtCloser, error) {
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

func OpenStoreCoredump(store *modulestore.Store, coreFileRef modulestore.ID, modules []ModuleInfo) (
	process.Process, error) {
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

		store:   store,
		modules: moduleMap,
	}, nil
}
