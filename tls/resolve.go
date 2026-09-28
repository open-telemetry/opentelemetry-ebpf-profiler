// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"debug/elf"
	"fmt"
	"maps"
	"slices"

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

// ResolveResult contains the access path or error for one input to ResolveMany.
// Var is usable only when Err is nil.
type ResolveResult struct {
	Var Var
	Err error
}

// Resolve selects an access path to sym, a thread-local variable defined by ef.
// It is the single-symbol form of ResolveMany.
func Resolve(ef *pfelf.File, sym *libpf.Symbol) (Var, error) {
	results, err := ResolveMany(ef, []*libpf.Symbol{sym})
	if err != nil {
		return Var{}, err
	}
	return results[0].Var, results[0].Err
}

// ResolveMany selects access paths to thread-local variables defined by ef,
// sharing one relocation walk. Each returned Var can be located using Locate.
// Results have the same length and order as syms, including duplicate inputs.
// An empty batch returns an empty result without inspecting ef.
//
// Each result reports ErrNotThreadLocal for a nil, undefined or non-TLS symbol,
// or ErrUnsupportedModel when no access path is found or the architecture is
// unsupported. Other symbol-specific failures, such as invalid static TLS
// offsets, are also reported in the corresponding result.
// A failed relocation walk returns a batch error and no results.
//
// The available access paths depend on the relocations:
//   - TLSDESC                   -> general/local-dynamic, GNU2/desc dialect
//   - DTPMOD64 referencing sym  -> general-dynamic, GNU dialect
//   - DTPMOD64 without a symbol -> local-dynamic, GNU dialect
//   - TPOFF64                   -> initial-exec
//   - no relocation, executable -> local-exec (static TLS block)
//
// Relocations for hidden symbols may omit the symbol name. ResolveMany then uses
// relocations for the defining module and their addends to locate the variables.
func ResolveMany(ef *pfelf.File, syms []*libpf.Symbol) ([]ResolveResult, error) {
	results := make([]ResolveResult, len(syms))
	named := make(map[string]relocationTargets)
	for i, sym := range syms {
		switch {
		case sym == nil:
			results[i].Err = fmt.Errorf("%w: nil symbol", ErrNotThreadLocal)
		case sym.Shndx == uint16(elf.SHN_UNDEF):
			results[i].Err = fmt.Errorf("%w: %s is undefined", ErrNotThreadLocal, sym.Name)
		case elf.ST_TYPE(sym.Info) != elf.STT_TLS:
			results[i].Err = fmt.Errorf("%w: %s is of type %v", ErrNotThreadLocal, sym.Name,
				elf.ST_TYPE(sym.Info))
		default:
			// Symbols sharing a name can reuse named relocation targets even
			// when their offsets differ for symbol-less matching.
			named[string(sym.Name)] = relocationTargets{}
		}
	}
	if len(named) == 0 {
		return results, nil
	}

	variant, err := tlsVariantOf(ef.Machine)
	if err != nil {
		for i := range results {
			if results[i].Err == nil {
				results[i].Err = err
			}
		}
		return results, nil
	}

	// Symbol-less relocations are shared by the batch. DTPMOD64 identifies the
	// module alone; TLSDESC and TPOFF64 addends identify offsets within it.
	var tpmodNoSymAddr libpf.Address
	tlsdescNoSym := make(map[int64]libpf.Address)
	tpoffNoSym := make(map[int64]libpf.Address)
	// Empty names remain pending: they require symbol-less matching, so no
	// named TPOFF64 can finish their search early.
	pending := len(named)

	if err = ef.VisitRelocations(func(r pfelf.ElfReloc, symName string,
		relType pfelf.RelocType) bool {
		if symName != "" {
			targets, ok := named[symName]
			if !ok || targets.tpoffAddr != 0 {
				return true
			}
			// Keep the first match for each type; choose between types below.
			switch relType {
			case pfelf.RelTLSDESC:
				if targets.tlsdescAddr == 0 {
					targets.tlsdescAddr = libpf.Address(r.Off)
				}
			case pfelf.RelDTPMOD64:
				if targets.tpmodAddr == 0 {
					targets.tpmodAddr = libpf.Address(r.Off)
				}
			case pfelf.RelTPOFF64:
				targets.tpoffAddr = libpf.Address(r.Off)
				if targets.tpoffAddr != 0 {
					pending--
				}
			}
			named[symName] = targets
		} else {
			switch relType {
			case pfelf.RelTLSDESC:
				if _, exists := tlsdescNoSym[r.Addend]; !exists && r.Addend >= 0 {
					tlsdescNoSym[r.Addend] = libpf.Address(r.Off)
				}
			case pfelf.RelDTPMOD64:
				// Only the module ID is relocated, so any such slot can be used.
				if tpmodNoSymAddr == 0 {
					tpmodNoSymAddr = libpf.Address(r.Off)
				}
			case pfelf.RelTPOFF64:
				if tpoffNoSym[r.Addend] == 0 {
					tpoffNoSym[r.Addend] = libpf.Address(r.Off)
				}
			}
		}
		// Stop once every valid input has the highest-priority access path.
		return pending != 0
	}, pfelf.RelTLSDESC|pfelf.RelDTPMOD64|pfelf.RelTPOFF64); err != nil {
		return nil, fmt.Errorf("failed to visit TLS relocations: %w", err)
	}

	// A symbol-less descriptor locates module_base + addend. Select the largest
	// addend at or below each symbol, then let Locate add the remaining offset.
	// x86-64 commonly uses one module-base descriptor (addend 0), while aarch64
	// uses per-variable descriptors. Sorting once avoids a scan per symbol.
	addends := slices.Sorted(maps.Keys(tlsdescNoSym))
	for i, sym := range syms {
		if results[i].Err != nil {
			continue
		}
		unnamed := relocationTargets{
			tpmodAddr: tpmodNoSymAddr,
			tpoffAddr: tpoffNoSym[int64(sym.Address)],
		}
		var tlsdescAddend uint64
		j, exact := slices.BinarySearch(addends, int64(sym.Address))
		if !exact {
			j--
		}
		if j >= 0 {
			addend := addends[j]
			unnamed.tlsdescAddr = tlsdescNoSym[addend]
			tlsdescAddend = uint64(sym.Address) - uint64(addend)
		}
		results[i].Var, results[i].Err = resolveCandidates(ef, sym, variant,
			named[string(sym.Name)], unnamed, tlsdescAddend)
	}
	return results, nil
}

type relocationTargets struct {
	tlsdescAddr libpf.Address
	tpmodAddr   libpf.Address
	tpoffAddr   libpf.Address
}

func resolveCandidates(ef *pfelf.File, sym *libpf.Symbol, variant tlsVariant,
	named, unnamed relocationTargets, tlsdescAddend uint64,
) (Var, error) {
	// Prefer paths that avoid a DTV lookup: TPOFF64 provides a TP-relative
	// offset, TLSDESC may provide one, and DTPMOD64 always requires the DTV.
	// Within each type, prefer a relocation naming sym over a symbol-less one.
	for _, m := range []struct {
		addr   libpf.Address
		access accessModel
		addend uint64
	}{
		{named.tpoffAddr, accessInitialExec, 0},
		{unnamed.tpoffAddr, accessInitialExec, 0},
		{named.tlsdescAddr, accessTLSDesc, 0},
		{unnamed.tlsdescAddr, accessTLSDesc, tlsdescAddend},
		{named.tpmodAddr, accessGeneralDynamic, 0},
		{unnamed.tpmodAddr, accessLocalDynamic, uint64(sym.Address)},
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
