// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import (
	"debug/elf"
	"errors"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// tlsAccess identifies how the otel_thread_ctx_v1 TLS variable is accessed,
// which determines how its address is resolved at attach time.
type tlsAccess uint8

const (
	// accessTLSDesc: a TLS descriptor (GNU2/desc dialect) whose resolved argument
	// is either a static TP-relative offset or a pointer to a tls_index struct
	// for dynamic TLS. Covers general-dynamic and local-dynamic.
	accessTLSDesc tlsAccess = iota
	// accessLocalExec: the variable lives in the static TLS block and its
	// TP-relative offset is known at load time.
	accessLocalExec
	// accessInitialExec: a GOT slot holds the variable's TP-relative offset,
	// filled in by the dynamic loader.
	accessInitialExec
	// accessLocalDynamic: a GOT tls_index whose module_id is filled in by the
	// loader, but whose in-module offset is the symbol's static value
	// (GNU dialect, local-dynamic).
	accessLocalDynamic
	// accessGlobalDynamic: a GOT tls_index {module_id, offset} pair (GNU dialect,
	// general-dynamic), both words filled in by the dynamic loader.
	accessGlobalDynamic
)

func (a tlsAccess) String() string {
	switch a {
	case accessTLSDesc:
		return "tlsdesc"
	case accessLocalExec:
		return "local-exec"
	case accessInitialExec:
		return "initial-exec"
	case accessLocalDynamic:
		return "local-dynamic"
	case accessGlobalDynamic:
		return "global-dynamic"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(a))
	}
}

// resolveTLSAccess determines how the otel_thread_ctx_v1 TLS variable is
// accessed, covering both TLS dialects (GNU and GNU2/desc) and all four access
// models (local-exec, initial-exec, general-dynamic and local-dynamic).
//
// The access model and dialect are inferred from the relocation type that
// references the symbol:
//   - TLSDESC                        -> general/local-dynamic, GNU2/desc dialect
//   - DTPMOD64 (+ DTPOFF64 GOT slot) -> general-dynamic, GNU dialect
//   - TPOFF64                        -> initial-exec
//   - no relocation, executable      -> local-exec (static TLS block)
//
// The local-dynamic model is special: the relocation does not reference the
// symbol but the module (symbol index 0), because the per-variable offset is
// resolved separately in code. In that case the in-module offset is the
// symbol's static value (offset).
func resolveTLSAccess(ef *pfelf.File, sym *libpf.Symbol) (*data, error) {
	var tlsdescAddr, tpmodAddr, tpoffAddr libpf.Address
	// Module-level relocations (not referencing any symbol) are local-dynamic
	// candidates: we keep the first one of each dialect as a fallback.
	var tlsdescNoSymAddr, tpmodNoSymAddr libpf.Address

	if err := ef.VisitRelocations(func(r pfelf.ElfReloc, symName string,
		relType pfelf.RelocType) bool {
		switch symName {
		case tlsExport:
			switch relType {
			case pfelf.RelTLSDESC:
				tlsdescAddr = libpf.Address(r.Off)
			case pfelf.RelDTPMOD64:
				tpmodAddr = libpf.Address(r.Off)
			case pfelf.RelTPOFF64:
				tpoffAddr = libpf.Address(r.Off)
			}
			return false
		case "":
			switch relType {
			case pfelf.RelTLSDESC:
				if tlsdescNoSymAddr == 0 {
					tlsdescNoSymAddr = libpf.Address(r.Off)
				}
			case pfelf.RelDTPMOD64:
				if tpmodNoSymAddr == 0 {
					tpmodNoSymAddr = libpf.Address(r.Off)
				}
			}
		}
		return true
	}, pfelf.RelTLSDESC|pfelf.RelDTPMOD64|pfelf.RelTPOFF64); err != nil {
		return nil, fmt.Errorf("failed to visit TLS relocations: %v", err)
	}

	switch {
	case tlsdescAddr != 0:
		// General-dynamic, GNU2/desc dialect.
		return &data{access: accessTLSDesc, elfAddr: tlsdescAddr}, nil
	case tpmodAddr != 0:
		// General-dynamic, GNU dialect.
		return &data{access: accessGlobalDynamic, elfAddr: tpmodAddr}, nil
	case tpoffAddr != 0:
		// Initial-exec.
		return &data{access: accessInitialExec, elfAddr: tpoffAddr}, nil
	}

	// Local-dynamic: the symbol is local to a shared object (not preemptible).
	// The module-level relocation provides the module ID at runtime, the in-module
	// offset is the symbol's static value.
	switch {
	case tlsdescNoSymAddr != 0:
		return &data{access: accessTLSDesc, elfAddr: tlsdescNoSymAddr,
			offset: uint64(sym.Address)}, nil
	case tpmodNoSymAddr != 0:
		return &data{access: accessLocalDynamic, elfAddr: tpmodNoSymAddr,
			offset: uint64(sym.Address)}, nil
	}

	// No relocation references the symbol directly.
	if isExecutable(ef) {
		// Local-exec: the variable lives in the main executable's static TLS
		// block and its TP-relative offset is known at load time.
		tlsOffset, err := getStaticTLSOffset(ef, sym)
		if err != nil {
			return nil, fmt.Errorf("failed to get static TLS offset: %v", err)
		}
		return &data{access: accessLocalExec, offset: tlsOffset}, nil
	}

	return nil, errors.New("unsupported TLS model")
}

func isExecutable(ef *pfelf.File) bool {
	switch ef.Type {
	case elf.ET_EXEC:
		// Classic, non-PIE executable.
		return true

	case elf.ET_DYN:
		// Ambiguous: either a shared library or a PIE executable.
		// The DF_1_PIE flag is the canonical discriminator.
		if vals, err := ef.DynValue(elf.DT_FLAGS_1); err == nil {
			for _, v := range vals {
				if v&uint64(elf.DF_1_PIE) != 0 {
					return true
				}
			}
		}
		// Fallback for older toolchains that didn't emit DF_1_PIE:
		// a dynamically-linked executable carries a PT_INTERP segment,
		// whereas a plain shared library does not.
		// This fallback is not perfect:
		// - libc.so.6 is a shared library, but has an interpreter segment.
		// - a statically-linked PIE executable might does not have an interpreter segment.
		for _, p := range ef.Progs {
			if p.Type == elf.PT_INTERP {
				return true
			}
		}
	}

	return false
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

// getStaticTLSOffset computes the thread-pointer-relative offset of a local-exec
// TLS variable defined in the main executable's static TLS block. sym.Address is
// the symbol's offset within the PT_TLS image.
func getStaticTLSOffset(ef *pfelf.File, sym *libpf.Symbol) (uint64, error) {
	tlsProg := getTLSProg(ef)
	if tlsProg == nil {
		return 0, fmt.Errorf("failed to locate TLS segment")
	}
	align := uint64(tlsProg.Align)
	if align == 0 {
		align = 1
	}

	switch ef.Machine {
	case elf.EM_AARCH64:
		// Variant I: the static TLS block sits above TP, at the first
		// align-aligned offset past a 16-byte reserved area (TCB on glibc,
		// GAP_ABOVE_TP on musl).
		return roundUp(16, align) + uint64(sym.Address), nil
	case elf.EM_X86_64:
		// Variant II: the executable's TLS block sits immediately below TP, its
		// size rounded up to the block alignment.
		return uint64(sym.Address) - roundUp(uint64(tlsProg.Memsz), align), nil
	}
	return 0, fmt.Errorf("unsupported machine: %s", ef.Machine)
}
