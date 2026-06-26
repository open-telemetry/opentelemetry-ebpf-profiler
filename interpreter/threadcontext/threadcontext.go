// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package threadcontext implements a pseudo interpreter handler that reads the thread context from the TLS.
package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import (
	"debug/elf"
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
	tlsExport     = "otel_thread_ctx_v1"
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

func GetLoader(_ Config) interpreter.Loader {
	return loader
}

// loader implements interpreter.Loader.
func loader(_ interpreter.EbpfHandler, info *interpreter.LoaderInfo) (interpreter.Data, error) {
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

	d, err := resolveTLSAccess(ef, threadStorageSym)
	if err != nil {
		return nil, err
	}

	log.Infof("Native thread labels TLS access=%v elfAddr=0x%08X offset=0x%08X",
		d.access, d.elfAddr, d.offset)

	return d, nil
}

type data struct {
	// access selects how the TLS variable address is resolved at attach time.
	access tlsAccess
	// elfAddr is the (unbiased) ELF address of the TLS descriptor or GOT slot
	// used by the initial-exec, tlsdesc and gnu-dynamic access models.
	elfAddr libpf.Address
	// offset is a statically-known offset added to the base resolved at runtime.
	// For local-exec the runtime base is zero, so it holds the full TP-relative
	// offset. For local-dynamic it holds the symbol's static value (the relocation
	// only resolves the module, not the per-variable offset). It is zero for the
	// other models, where the offset is fully resolved at runtime.
	offset uint64
}

var _ interpreter.Data = &data{}

func (d data) String() string {
	return "Native thread labels"
}

func (d data) Attach(ebpf interpreter.EbpfHandler, pid libpf.PID,
	bias libpf.Address, rm remotememory.RemoteMemory,
) (interpreter.Instance, error) {
	switch d.access {
	case accessLocalExec:
		return d.attachStatic(ebpf, pid, d.offset)

	case accessInitialExec:
		// The GOT slot holds the variable's TP-relative offset directly.
		return d.attachStatic(ebpf, pid, rm.Uint64(bias+d.elfAddr)+d.offset)

	case accessGlobalDynamic:
		// The GOT holds a tls_index {module_id, offset} pair.
		moduleID := rm.Uint64(bias + d.elfAddr)
		tlsOffset := rm.Uint64(bias+d.elfAddr+8) + d.offset
		return attachDynamic(pid, moduleID, tlsOffset)

	case accessLocalDynamic:
		// The GOT holds the module_id; the in-module offset is the symbol value.
		moduleID := rm.Uint64(bias + d.elfAddr)
		return attachDynamic(pid, moduleID, d.offset)

	case accessTLSDesc:
		// The second word of the descriptor holds the resolved argument.
		arg := rm.Uint64(bias + d.elfAddr + 8)

		// If dynamic TLS is used, arg is a pointer to a tls_index structure.
		// On x86_64, the offset is negative so it is easy to distinguish between
		// dynamic and static TLS. On aarch64, the offset is positive so we use an
		// arbitrary size to distinguish between dynamic and static TLS.
		if int64(arg) > 0xffffffff {
			moduleID := rm.Uint64(libpf.Address(arg))
			tlsOffset := rm.Uint64(libpf.Address(arg+8)) + d.offset
			return attachDynamic(pid, moduleID, tlsOffset)
		}
		return d.attachStatic(ebpf, pid, arg+d.offset)

	default:
		return nil, fmt.Errorf("unknown TLS access model %v", d.access)
	}
}

// attachStatic stores a static TP-relative TLS offset (no DTV indirection).
func (d data) attachStatic(ebpf interpreter.EbpfHandler, pid libpf.PID,
	tlsOffset uint64,
) (interpreter.Instance, error) {
	log.Infof("PID %d tls offset: 0x%08X", pid, tlsOffset)

	procInfo := support.ThreadContextProcInfo{
		Tls_offset:    int32(int64(tlsOffset)),
		Dtv_offset:    0,
		Module_offset: 0,
	}
	if err := ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	return &Instance{}, nil
}

// attachDynamic records a dynamic-TLS (DTV-based) access. Proc data is not
// updated here: the DTV offset/multiplier are only known once libc info is
// available (see Instance.UpdateLibcInfo).
func attachDynamic(pid libpf.PID, moduleID, tlsOffset uint64,
) (interpreter.Instance, error) {
	if moduleID == 0 {
		return nil, fmt.Errorf("unexpected value 0 for moduleID in dynamic TLS")
	}

	log.Infof("PID %d dynamic TLS moduleID: %d, tls offset: 0x%08X", pid, moduleID, tlsOffset)

	return &Instance{
		tlsOffset: int32(int64(tlsOffset)),
		moduleID:  int32(int64(moduleID)),
	}, nil
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
	if i.moduleID == 0 || !info.HasDTVInfo() {
		return nil
	}
	procInfo := support.ThreadContextProcInfo{
		Tls_offset:    i.tlsOffset,
		Dtv_offset:    int32(info.DTVInfo.Offset),
		Module_offset: i.moduleID * int32(info.DTVInfo.Multiplier),
	}
	return ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo))
}
