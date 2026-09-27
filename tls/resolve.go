// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"debug/elf"
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

// Resolve selects an access path to sym, a thread-local variable defined by ef.
// The returned Var can then be located in a process using Locate.
//
// The available access paths depend on the relocations:
//   - TLSDESC                   -> general/local-dynamic, GNU2/desc dialect
//   - DTPMOD64 referencing sym  -> general-dynamic, GNU dialect
//   - DTPMOD64 without a symbol -> local-dynamic, GNU dialect
//   - TPOFF64                   -> initial-exec
//   - no relocation, executable -> local-exec (static TLS block)
//
// Relocations for hidden symbols may omit the symbol name. Resolve then uses
// relocations for the defining module and their addends to locate the variable.
//
// Resolve returns ErrNotThreadLocal if sym is undefined or not STT_TLS, and
// ErrUnsupportedModel if no access path is found or the architecture is unsupported.
func Resolve(ef *pfelf.File, sym *libpf.Symbol) (Var, error) {
	// Only resolve variables defined by this ELF.
	if sym.Shndx == uint16(elf.SHN_UNDEF) {
		return Var{}, fmt.Errorf("%w: %s is undefined", ErrNotThreadLocal, sym.Name)
	}
	// Only STT_TLS symbol values are offsets within a TLS block.
	if elf.ST_TYPE(sym.Info) != elf.STT_TLS {
		return Var{}, fmt.Errorf("%w: %s is of type %v", ErrNotThreadLocal, sym.Name,
			elf.ST_TYPE(sym.Info))
	}

	variant, err := tlsVariantOf(ef.Machine)
	if err != nil {
		return Var{}, err
	}

	// Relocation targets for references to sym by name.
	var tlsdescAddr, tpmodAddr, tpoffAddr libpf.Address
	// Symbol-less relocations refer to this module; their addends may identify
	// an individual variable.
	var tlsdescNoSymAddr, tpmodNoSymAddr, tpoffNoSymAddr libpf.Address
	// Offset Locate must add to the address represented by the selected TLSDESC.
	var tlsdescNoSymAddend uint64
	// Start below zero so a descriptor with addend 0 is eligible.
	matchedRelAddend := int64(-1)

	if err = ef.VisitRelocations(func(r pfelf.ElfReloc, symName string,
		relType pfelf.RelocType) bool {
		switch {
		// Empty names must use the module-relative matching below.
		case symName != "" && symName == string(sym.Name):
			// Keep the first match for each type; choose between types below.
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
				// The descriptor locates module_base + r.Addend. Locate adds
				// sym.Address - r.Addend to reach the variable. x86-64 commonly
				// uses a module-base descriptor (addend 0), while aarch64 uses
				// per-variable descriptors. Choose the largest addend at or
				// below sym.Address to minimize the non-negative adjustment.
				if r.Addend > matchedRelAddend && r.Addend <= int64(sym.Address) {
					tlsdescNoSymAddr = libpf.Address(r.Off)
					matchedRelAddend = r.Addend
					tlsdescNoSymAddend = uint64(sym.Address) - uint64(r.Addend)
				}
			case pfelf.RelDTPMOD64:
				// Only the module ID is relocated, so any such slot can be used.
				if tpmodNoSymAddr == 0 {
					tpmodNoSymAddr = libpf.Address(r.Off)
				}
			case pfelf.RelTPOFF64:
				// The addend must identify this variable within the module.
				if tpoffNoSymAddr == 0 && r.Addend == int64(sym.Address) {
					tpoffNoSymAddr = libpf.Address(r.Off)
				}
			}
		}
		// No later relocation can take precedence over a named TPOFF64.
		return tpoffAddr == 0
	}, pfelf.RelTLSDESC|pfelf.RelDTPMOD64|pfelf.RelTPOFF64); err != nil {
		return Var{}, fmt.Errorf("failed to visit TLS relocations: %w", err)
	}

	// Prefer paths that avoid a DTV lookup: TPOFF64 provides a TP-relative
	// offset, TLSDESC may provide one, and DTPMOD64 always requires the DTV.
	// Within each type, prefer a relocation naming sym over a symbol-less one.
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

	// With no usable relocation, fall back to the executable's static TLS layout.
	if ef.IsExecutable() {
		tlsOffset, err := ef.StaticTLSOffset(sym)
		if err != nil {
			return Var{}, fmt.Errorf("failed to get static TLS offset: %w", err)
		}
		return Var{access: accessLocalExec, addend: tlsOffset, variant: variant}, nil
	}

	return Var{}, ErrUnsupportedModel
}
