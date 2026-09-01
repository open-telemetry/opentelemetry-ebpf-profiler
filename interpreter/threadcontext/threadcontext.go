// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package threadcontext implements a pseudo interpreter handler that reads the thread context from the TLS.
package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"math"
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

// readUint64 reads a 64-bit value from remote memory. Unlike rm.Uint64, a
// failed read is reported as an error rather than folded into 0 -- 0 is a
// value the TLS access models below treat as meaningful (unresolved
// relocation), so it must stay distinguishable from "the read itself failed".
func readUint64(rm remotememory.RemoteMemory, addr libpf.Address) (uint64, error) {
	var buf [8]byte
	if err := rm.Read(addr, buf[:]); err != nil {
		return 0, fmt.Errorf("failed to read remote memory at 0x%x: %w", addr, err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

const (
	// minUserAddr is the default mmap_min_addr: the kernel maps nothing below
	// it, so a value under it cannot be a pointer.
	minUserAddr = 0x10000
	// maxTLSModuleID bounds a plausible TLS module index. Loaders assign these
	// sequentially from 1.
	maxTLSModuleID = 4096
)

// tlsIndex is the {module, offset} pair a dynamic TLS descriptor's argument
// points at. glibc (tlsdesc_dynamic_arg) and musl both start that block with it.
type tlsIndex struct {
	moduleID uint64
	offset   uint64
}

// readTLSIndex interprets addr as a pointer to a tls_index, returning nil when
// it is not one.
//
// A TLS descriptor's argument is either such a pointer (dynamic TLS) or a
// TP-relative offset (static TLS), and magnitude cannot separate them: on
// aarch64 both are positive, a program with megabytes of thread-locals produces
// an offset larger than a non-PIE process's heap addresses, and that heap is
// exactly where the loader allocates the tls_index. So dereference it instead:
// a pointer yields a small module index, an offset points at nothing mapped.
func readTLSIndex(rm remotememory.RemoteMemory, addr uint64) (*tlsIndex, error) {
	if addr < minUserAddr {
		return nil, nil
	}
	moduleID, err := readUint64(rm, libpf.Address(addr))
	if err != nil || moduleID == 0 || moduleID > maxTLSModuleID {
		// Unreadable or implausible: not a pointer, so a large static offset.
		return nil, nil
	}
	offset, err := readUint64(rm, libpf.Address(addr+8))
	if err != nil {
		return nil, err
	}
	return &tlsIndex{moduleID: moduleID, offset: offset}, nil
}

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

	log.Debugf("Native thread labels TLS access=%v elfAddr=0x%08X offset=0x%08X",
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
	// machine is the ELF's target architecture, needed to tell a genuinely
	// unresolved GOT slot from a legitimately zero TP-relative offset (see
	// the accessInitialExec case in Attach).
	machine elf.Machine
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
		got, err := readUint64(rm, bias+d.elfAddr)
		if err != nil {
			return nil, err
		}
		// On x86-64 (TLS variant II, block below TP) a real offset can never
		// be 0: the block's own size keeps it strictly negative. On aarch64
		// (variant I, block above TP) 0 is ambiguous -- musl can legitimately
		// place a module's block starting exactly at TP (no reserved gap),
		// unlike glibc, which reserves 16 bytes above TP first. aarch64
		// accepts 0 here, trading away detection of the unresolved-at-startup case.
		if got == 0 && d.machine == elf.EM_X86_64 {
			return nil, fmt.Errorf("unresolved TLS GOT slot")
		}
		return d.attachStatic(ebpf, pid, got+d.offset)

	case accessGlobalDynamic:
		// The GOT holds a tls_index {module_id, offset} pair.
		moduleID, err := readUint64(rm, bias+d.elfAddr)
		if err != nil {
			return nil, err
		}
		rawOffset, err := readUint64(rm, bias+d.elfAddr+8)
		if err != nil {
			return nil, err
		}
		return attachDynamic(pid, moduleID, rawOffset+d.offset)

	case accessLocalDynamic:
		// The GOT holds the module_id; the in-module offset is the symbol value.
		moduleID, err := readUint64(rm, bias+d.elfAddr)
		if err != nil {
			return nil, err
		}
		return attachDynamic(pid, moduleID, d.offset)

	case accessTLSDesc:
		// The descriptor's first word is the resolver function pointer, set to
		// a non-null address as soon as the dynamic linker processes the
		// relocation -- unlike the second word, it can never legitimately be
		// 0, making it the reliable "not yet relocated" signal.
		//
		// The argument word can't be used for that instead: musl's static
		// resolver stores a real TP-relative offset there that is 0 whenever
		// a module's static TLS block starts exactly at the thread pointer
		// (glibc reserves 16 bytes above TP first, so this never happens for it).
		resolver, err := readUint64(rm, bias+d.elfAddr)
		if err != nil {
			return nil, err
		}
		if resolver == 0 {
			return nil, fmt.Errorf("unresolved TLSDESC descriptor")
		}

		// The second word of the descriptor holds the resolved argument.
		arg, err := readUint64(rm, bias+d.elfAddr+8)
		if err != nil {
			return nil, err
		}

		ti, err := readTLSIndex(rm, arg)
		if err != nil {
			return nil, err
		}
		if ti != nil {
			return attachDynamic(pid, ti.moduleID, ti.offset+d.offset)
		}
		return d.attachStatic(ebpf, pid, arg+d.offset)

	default:
		return nil, fmt.Errorf("unknown TLS access model %v", d.access)
	}
}

// s32FromUint64 narrows v to an int32, rejecting values that don't fit.
// x86-64 local-exec offsets are computed as a uint64 underflow (a small
// negative number stored via wraparound), so int32(int64(v)) recovers the
// right value for realistic magnitudes but would silently wrap on anything
// larger -- worth rejecting rather than trusting.
func s32FromUint64(v uint64) (int32, error) {
	s := int64(v)
	if s != int64(int32(s)) {
		return 0, fmt.Errorf("value %#x does not fit in s32", v)
	}
	return int32(s), nil
}

// attachStatic stores a static TP-relative TLS offset (no DTV indirection).
// Callers are responsible for rejecting an unresolved runtime read before
// calling this: unlike accessLocalExec/accessInitialExec, the TLSDesc-static
// caller can legitimately pass 0 here (see the accessTLSDesc case in Attach).
func (d data) attachStatic(ebpf interpreter.EbpfHandler, pid libpf.PID,
	tlsOffset uint64,
) (interpreter.Instance, error) {
	offset, err := s32FromUint64(tlsOffset)
	if err != nil {
		return nil, fmt.Errorf("TLS offset: %w", err)
	}

	log.Debugf("PID %d tls offset: 0x%08X", pid, tlsOffset)

	// module_id == 0 marks static TLS: no DTV indirection at unwind time.
	procInfo := support.ThreadContextProcInfo{
		Tls_offset: offset,
	}
	if err := ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo)); err != nil {
		return nil, err
	}

	return &Instance{procDataWritten: true}, nil
}

// attachDynamic records a dynamic-TLS (DTV-based) access. Proc data is not
// updated here: the DTV offset/multiplier are only known once libc info is
// available (see Instance.UpdateLibcInfo).
func attachDynamic(pid libpf.PID, moduleID, tlsOffset uint64,
) (interpreter.Instance, error) {
	if moduleID == 0 {
		return nil, fmt.Errorf("unexpected value 0 for moduleID in dynamic TLS")
	}
	if moduleID > math.MaxUint32 {
		return nil, fmt.Errorf("moduleID %#x does not fit in u32", moduleID)
	}
	offset, err := s32FromUint64(tlsOffset)
	if err != nil {
		return nil, fmt.Errorf("TLS offset: %w", err)
	}

	log.Debugf("PID %d dynamic TLS moduleID: %d, tls offset: 0x%08X", pid, moduleID, tlsOffset)

	return &Instance{
		tlsOffset: offset,
		moduleID:  uint32(moduleID),
	}, nil
}

func (d data) Unload(_ interpreter.EbpfHandler) {
}

type Instance struct {
	tlsOffset int32
	moduleID  uint32
	// procDataWritten is true once proc data has actually been installed in
	// eBPF: immediately for static TLS (attachStatic), or once libc DTV info
	// arrives for dynamic TLS (UpdateLibcInfo). Detach must not delete proc
	// data that was never written.
	procDataWritten bool
	interpreter.InstanceStubs
}

var _ interpreter.Instance = &Instance{}

// Detach implements the interpreter.Instance interface.
func (i *Instance) Detach(ebpf interpreter.EbpfHandler, pid libpf.PID) error {
	if !i.procDataWritten {
		// Dynamic-TLS process whose libc DTV info never arrived: no proc
		// data was ever installed, nothing to delete.
		log.Debugf("PID %d: no thread-context proc data was ever installed "+
			"(dynamic TLS, DTV info never arrived)", pid)
		return nil
	}
	return ebpf.DeleteProcData(libpf.ThreadContext, pid)
}

// UpdateLibcInfo installs the dynamic-TLS proc data deferred by attachDynamic,
// once libc DTV introspection succeeds. Static-TLS instances wrote theirs in
// attachStatic, so procDataWritten short-circuits them here too.
func (i *Instance) UpdateLibcInfo(ebpf interpreter.EbpfHandler, pid libpf.PID, info libc.LibcInfo) error {
	if i.procDataWritten || !info.HasDTVInfo() {
		return nil
	}
	procInfo := support.ThreadContextProcInfo{
		Tls_offset: i.tlsOffset,
		Module_id:  i.moduleID,
		Dtv_info:   info.DTVInfo,
	}
	if err := ebpf.UpdateProcData(libpf.ThreadContext, pid, unsafe.Pointer(&procInfo)); err != nil {
		return err
	}
	i.procDataWritten = true
	return nil
}
