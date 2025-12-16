// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package threadcontext implements a pseudo interpreter handler that reads the thread context from the TLS.
package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import (
	"debug/elf"
	"errors"
	"fmt"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libc"

	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	// tlsExport defines the name of the thread info TLS export.
	tlsExport     = "custom_labels_current_set_v2"
	tlsExportSize = 8
)

func findSymbol(ef *pfelf.File, symname string) *libpf.Symbol {
	sym, err := ef.LookupSymbol(libpf.SymbolName(symname))
	if err != nil {
		// Lookup symbol might not find the symbol if it is not in the ELF hash table (DT_GNU_HASH).
		// Only dynamic symbols are referenced in the ELF hash table
		// (for example symbols from an executable or local symbols from a shared library are not referenced).
		ef.VisitSymbols(func(s libpf.Symbol) bool {
			if s.Name == libpf.SymbolName(symname) {
				sym = &s
				return false
			}
			return true
		})
	}

	return sym
}

func isExecutable(ef *pfelf.File) bool {
	if ef.Type == elf.ET_EXEC {
		return true
	}
	// Position-independent executables (PIE) are typically marked as ET_DYN.
	// Distinguish them from shared libraries by checking for an interpreter
	// segment and at least one executable PT_LOAD segment.
	// This is not foolproof:
	// libc.so.6 is a shared library, but has an interpreter segment and an executable PT_LOAD segment.
	// The way readelf does it is to check if DF_1_PIE is set in the dynamic flags (DT_FLAGS_1).
	if ef.Type != elf.ET_DYN || ef.Entry == 0 {
		return false
	}
	hasInterp := false
	hasExecLoad := false
	for _, prog := range ef.Progs {
		if prog.Type == elf.PT_INTERP {
			hasInterp = true
			continue
		}
		if prog.Type == elf.PT_LOAD && (prog.Flags&elf.PF_X) != 0 {
			hasExecLoad = true
		}
	}
	return hasInterp && hasExecLoad
}

// Loader implements interpreter.Loader.
func Loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
	ef, err := info.GetELF()
	if err != nil {
		return nil, err
	}

	// Resolve process storage symbol.
	threadStorageSym := findSymbol(ef, tlsExport)
	if threadStorageSym == nil {
		return nil, nil
	}

	if threadStorageSym.Size != tlsExportSize {
		return nil, fmt.Errorf("TLS export has wrong size %d", threadStorageSym.Size)
	}

	if elf.ST_TYPE(threadStorageSym.Info) != elf.STT_TLS {
		return nil, fmt.Errorf("TLS export is not a TLS symbol")
	}

	var tlsDescElfAddr libpf.Address
	var tlsOffset uint64
	if err = ef.VisitTLSRelocations(func(r pfelf.ElfReloc, symName string) bool {
		if symName == tlsExport {
			tlsDescElfAddr = libpf.Address(r.Off)
			return false
		}
		return true
	}); err != nil {
		return nil, fmt.Errorf("failed to visit TLS descriptor: %v", err)
	}

	if tlsDescElfAddr == 0 {
		// No TLS descriptor found, 2 possible reasons:
		// 1. TLS dialect is not TLS desc
		// 2. No relocation found because local/initial exec TLS model (executable) or local dynamic TLS model

		// For now only support executable TLS model.
		if !isExecutable(ef) {
			return nil, errors.New("unsupported TLS model")
		}
		tlsOffset, err = getStaticTLSOffset(ef, threadStorageSym)
		if err != nil {
			return nil, fmt.Errorf("failed to get static TLS offset: %v", err)
		}
	}
	log.Infof("Native thread labels TLS descriptor address: 0x%08X, TLS offset: 0x%08X", tlsDescElfAddr, tlsOffset)

	return &data{
		tlsDescElfAddr: tlsDescElfAddr,
		tlsOffset:      tlsOffset,
	}, nil
}

func roundUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}

func getTLSProg(ef *pfelf.File) *pfelf.Prog {
	for _, prog := range ef.Progs {
		if prog.Type == elf.PT_TLS {
			return &prog
		}
	}
	return nil
}

func getStaticTLSOffset(ef *pfelf.File, threadStorageSym *libpf.Symbol) (uint64, error) {
	if ef.Machine == elf.EM_AARCH64 {
		return uint64(threadStorageSym.Address), nil
	}

	if ef.Machine == elf.EM_X86_64 {
		tlsProg := getTLSProg(ef)
		if tlsProg == nil {
			return 0, fmt.Errorf("failed to locate TLS segment")
		}
		return uint64(threadStorageSym.Address) - roundUp(uint64(tlsProg.Memsz), uint64(tlsProg.Align)), nil
	}
	return 0, fmt.Errorf("unsupported machine: %s", ef.Machine)
}

type data struct {
	tlsDescElfAddr libpf.Address
	tlsOffset      uint64
}

var _ interpreter.Data = &data{}

func (d data) String() string {
	return "Native thread labels"
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	var tlsOffset uint64
	if d.tlsOffset != 0 {
		tlsOffset = d.tlsOffset
	} else {
		// Read TLS offset from the TLS descriptor.
		tlsOffset = rm.Uint64(bias + d.tlsDescElfAddr + 8)

		// if dynamic TLS is used, tlsOffset will be a pointer to a tls_index structure.
		// use an arbitrary size to distinguish between dynamic and static TLS.
		if int64(tlsOffset) > 0x100000 {
			// dynamic TLS is used, read the tls_index structure.
			moduleID := rm.Uint64(libpf.Address(tlsOffset))
			tlsOffset = rm.Uint64(libpf.Address(tlsOffset + 8))

			if moduleID == 0 {
				return nil, fmt.Errorf("unexpected value 0 for moduleID in dynamic TLS")
			}

			log.Infof("PID %d dynamic TLS moduleID: %d, tls offset: 0x%08X", pid, moduleID, tlsOffset)

			// Do not update proc data here, wait for libc info to be available.
			return &Instance{
				tlsOffset: int32(int64(tlsOffset)),
				moduleID:  int32(int64(moduleID)),
			}, nil
		}
	}

	log.Infof("PID %d tls offset: 0x%08X", pid, tlsOffset)

	procInfo := support.ThreadContextProcInfo{Tls_offset: int32(int64(tlsOffset)), Dtv_offset: 0, Module_offset: 0}
	if err := ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	return &Instance{}, nil
}

func (d data) Unload(_ interpreter.EbpfHandler) {
}

type Instance struct {
	tlsOffset int32
	moduleID  int32
	interpreter.InstanceStubs
}

var _ interpreter.Instance = &Instance{}

// Detach implements the interpreter.Instance interface.
func (i *Instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	return ebpf.DeleteProcData(libpf.ThreadContext, pid)
}

func (i *Instance) UpdateLibcInfo(ebpf interpreter.EbpfHandler, pid libpf.PID, info libc.LibcInfo) error {
	if i.moduleID == 0 {
		return nil
	}
	procInfo := support.ThreadContextProcInfo{
		Tls_offset:    i.tlsOffset,
		Dtv_offset:    int32(info.DTVInfo.Offset),
		Module_offset: i.moduleID * int32(info.DTVInfo.Multiplier),
	}
	return ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo))
}
