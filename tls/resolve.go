// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// accessModel identifies how a TLS variable is accessed, which determines how
// its address is resolved at Locate time.
type accessModel uint8

const (
	// accessInvalid is the zero value, so a zero Var is not mistaken for a
	// descriptor at ELF address 0.
	accessInvalid accessModel = iota
	// accessTLSDesc: a TLS descriptor (GNU2/desc dialect) whose resolved argument
	// is either a static TP-relative offset or a pointer to a tls_index struct
	// for dynamic TLS. Covers general-dynamic and local-dynamic.
	accessTLSDesc
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
	// accessGeneralDynamic: a GOT tls_index {module_id, offset} pair (GNU
	// dialect), both words filled in by the dynamic loader.
	accessGeneralDynamic
)

func (a accessModel) String() string {
	switch a {
	case accessInvalid:
		return "invalid"
	case accessTLSDesc:
		return "tlsdesc"
	case accessLocalExec:
		return "local-exec"
	case accessInitialExec:
		return "initial-exec"
	case accessLocalDynamic:
		return "local-dynamic"
	case accessGeneralDynamic:
		return "general-dynamic"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(a))
	}
}

// Resolve determines how sym, a thread-local defined by ef, is accessed,
// returning ErrUnsupportedModel when no model fits or the architecture's TLS
// layout is unknown.
//
// The model follows from the relocation type that references the symbol:
//   - TLSDESC                   -> general/local-dynamic, GNU2/desc dialect
//   - DTPMOD64                  -> general-dynamic, GNU dialect
//   - TPOFF64                   -> initial-exec
//   - no relocation, executable -> local-exec (static TLS block)
//
// A hidden symbol is referenced by no relocation of its own, and is resolved
// through its module's instead.
func Resolve(ef *pfelf.File, sym *libpf.Symbol) (Var, error) {
	variant, err := tlsVariantOf(ef.Machine)
	if err != nil {
		return Var{}, err
	}

	var tlsdescAddr, tpmodAddr, tpoffAddr libpf.Address
	// Module-level relocations, referencing no symbol. DTPMOD64 resolves the
	// module ID alone, shared by every hidden variable in the object, so any
	// one of them will do. TPOFF64 is per-variable, so its addend has to match
	// sym.Address.
	var tlsdescNoSymAddr, tpmodNoSymAddr, tpoffNoSymAddr libpf.Address
	// Addend left for Locate by the matched descriptor, and the relocation
	// addend it was matched on. -1 so a first candidate with addend 0 still
	// wins.
	var tlsdescNoSymAddend uint64
	matchedRelAddend := int64(-1)

	if err = ef.VisitRelocations(func(r pfelf.ElfReloc, symName string,
		relType pfelf.RelocType) bool {
		switch {
		// The emptiness test keeps a nameless symbol out of this branch, where
		// it would shadow the symbol-less rows below. Those are the ones that
		// can resolve it: nothing references it by name.
		case symName != "" && symName == string(sym.Name):
			// Every slot is first-wins, and the scan runs to the end, so which
			// model a mixed-dialect object resolves to is the table below
			// rather than the order the linker emitted its sections in.
			switch relType {
			case pfelf.RelTLSDESC:
				if tlsdescAddr == 0 {
					tlsdescAddr = libpf.Address(r.Off)
				}
			case pfelf.RelDTPMOD64:
				if tpmodAddr == 0 {
					tpmodAddr = libpf.Address(r.Off)
				}
			case pfelf.RelTPOFF64:
				if tpoffAddr == 0 {
					tpoffAddr = libpf.Address(r.Off)
				}
			}
		case symName == "":
			switch relType {
			case pfelf.RelTLSDESC:
				// The loader resolves the descriptor to module_base + addend,
				// so what Locate must add is sym.Address - addend, for any
				// descriptor of this module: x86-64 emits one per module
				// (addend 0, against _TLS_MODULE_BASE_), aarch64 one per
				// variable carrying its own offset. The largest addend at or
				// below the symbol keeps that difference non-negative.
				if r.Addend > matchedRelAddend && r.Addend <= int64(sym.Address) {
					tlsdescNoSymAddr = libpf.Address(r.Off)
					matchedRelAddend = r.Addend
					tlsdescNoSymAddend = uint64(sym.Address) - uint64(r.Addend)
				}
			case pfelf.RelDTPMOD64:
				if tpmodNoSymAddr == 0 {
					tpmodNoSymAddr = libpf.Address(r.Off)
				}
			case pfelf.RelTPOFF64:
				if tpoffNoSymAddr == 0 && r.Addend == int64(sym.Address) {
					tpoffNoSymAddr = libpf.Address(r.Off)
				}
			}
		}
		return true
	}, pfelf.RelTLSDESC|pfelf.RelDTPMOD64|pfelf.RelTPOFF64); err != nil {
		return Var{}, fmt.Errorf("failed to visit TLS relocations: %w", err)
	}

	// Ranked by what the row leaves for the caller: TPOFF64 is a TP offset on
	// its own, TLSDESC is one too whenever its descriptor resolved to static,
	// and DTPMOD64 always needs the DTV. A named row beats its symbol-less
	// counterpart, which has only the addend to go by. All of them address the
	// same variable, so the rank picks an access path, not an answer.
	for _, m := range []struct {
		addr   libpf.Address
		access accessModel
		addend uint64
	}{
		{tpoffAddr, accessInitialExec, 0},
		{tpoffNoSymAddr, accessInitialExec, 0},
		{tlsdescAddr, accessTLSDesc, 0},
		{tlsdescNoSymAddr, accessTLSDesc, tlsdescNoSymAddend},
		{tpmodAddr, accessGeneralDynamic, 0},
		{tpmodNoSymAddr, accessLocalDynamic, uint64(sym.Address)},
	} {
		if m.addr != 0 {
			return Var{access: m.access, elfAddr: m.addr, addend: m.addend,
				variant: variant}, nil
		}
	}

	// No relocation references the symbol directly.
	if ef.IsExecutable() {
		// The executable's own PT_TLS offset is fixed at link time, so an
		// unreferenced symbol here is local-exec.
		tlsOffset, err := ef.StaticTLSOffset(sym)
		if err != nil {
			return Var{}, fmt.Errorf("failed to get static TLS offset: %w", err)
		}
		return Var{access: accessLocalExec, addend: tlsOffset, variant: variant}, nil
	}

	return Var{}, ErrUnsupportedModel
}
