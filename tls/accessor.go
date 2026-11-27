// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"debug/elf"
	"fmt"
	"math"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// maxAccessorSize is the maximum number of code bytes decoded from an accessor.
const maxAccessorSize = 512

// ResolveAccessor resolves the thread-local variable read by the function
// accessor. Use it for variables without a usable symbol, e.g. static ones.
//
// For executables the local-exec offset is decoded from the code. Otherwise
// the GOT slot or TLS descriptor is decoded and resolved via its relocation.
func ResolveAccessor(ef *pfelf.File, accessor libpf.SymbolName) (Var, error) {
	sym, code, err := ef.SymbolData(accessor, maxAccessorSize)
	if err != nil {
		return Var{}, fmt.Errorf("could not read %s: %w", accessor, err)
	}
	if ef.IsExecutable() {
		return resolveLocalExecAccessor(ef, accessor, sym, code)
	}
	return resolveSlotAccessor(ef, accessor, sym, code)
}

// resolveLocalExecAccessor decodes the local-exec TLS offset used by code.
func resolveLocalExecAccessor(ef *pfelf.File, accessor libpf.SymbolName,
	sym *libpf.Symbol, code []byte) (Var, error) {
	var offset int32
	var err error
	switch ef.Machine {
	case elf.EM_AARCH64:
		offset, err = arm.ExtractTLSOffset(code, uint64(sym.Address), ef)
	case elf.EM_X86_64:
		offset, err = amd.ExtractTLSOffset(code, uint64(sym.Address), nil)
	default:
		return Var{}, fmt.Errorf("unsupported architecture for assembly analysis: %v",
			ef.Machine)
	}
	if err != nil {
		return Var{}, fmt.Errorf("could not extract TLS offset from %s: %w",
			accessor, err)
	}

	variant, err := tlsVariantOf(ef.Machine)
	if err != nil {
		return Var{}, err
	}
	return Var{access: accessLocalExec, addend: uint64(int64(offset)),
		variant: variant}, nil
}

// resolveSlotAccessor decodes the GOT slot or TLS descriptor used by code
// and resolves the variable it refers to.
func resolveSlotAccessor(ef *pfelf.File, accessor libpf.SymbolName,
	sym *libpf.Symbol, code []byte) (Var, error) {
	var slot uint64
	var disp int64
	var err error
	switch ef.Machine {
	case elf.EM_AARCH64:
		slot, disp, err = arm.ExtractTLSSlot(code, uint64(sym.Address))
	case elf.EM_X86_64:
		slot, disp, err = amd.ExtractTLSSlot(code, uint64(sym.Address))
	default:
		return Var{}, fmt.Errorf("unsupported architecture for assembly analysis: %v",
			ef.Machine)
	}
	if err != nil {
		return Var{}, fmt.Errorf("could not extract TLS slot from %s: %w",
			accessor, err)
	}

	tlsVar, err := slotSymbol(ef, libpf.Address(slot), disp, tlsSlotRelocs, false)
	if err != nil {
		return Var{}, err
	}
	v, err := Resolve(ef, tlsVar)
	if err != nil {
		return Var{}, fmt.Errorf("could not resolve TLS access at 0x%x: %w", slot, err)
	}
	return v, nil
}

const tlsSlotRelocs = pfelf.RelTLSDESC | pfelf.RelDTPMOD64 | pfelf.RelTPOFF64

// AnonymousSlotSymbol identifies a hidden variable from a decoded TLS access.
// The relocation at slot must be symbol-less and match one of kinds. Address in
// the returned symbol is the module-relative offset, including disp, so callers
// can compare accesses through different slots before passing the symbol to Resolve.
func AnonymousSlotSymbol(ef *pfelf.File, slot libpf.Address, disp int64,
	kinds pfelf.RelocType) (*libpf.Symbol, error) {
	return slotSymbol(ef, slot, disp, kinds&tlsSlotRelocs, true)
}

func slotSymbol(ef *pfelf.File, slot libpf.Address, disp int64, kinds pfelf.RelocType,
	anonymousOnly bool) (*libpf.Symbol, error) {
	var found bool
	var reloc pfelf.ElfReloc
	var relocSym string
	var relocType pfelf.RelocType
	err := ef.VisitRelocations(func(r pfelf.ElfReloc, symName string,
		relType pfelf.RelocType) bool {
		if libpf.Address(r.Off) != slot {
			return true
		}
		found, reloc, relocSym, relocType = true, r, symName, relType
		return false
	}, kinds)
	if err != nil {
		return nil, fmt.Errorf("failed to visit TLS relocations: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("no TLS relocation for slot 0x%x", slot)
	}

	if anonymousOnly && (reloc.Info>>32 != 0 || relocSym != "") {
		return nil, fmt.Errorf("expected an anonymous TLS relocation at slot %#x", slot)
	}
	if relocSym != "" {
		if disp != 0 {
			return nil, fmt.Errorf("unexpected displacement %d for %s at slot 0x%x",
				disp, relocSym, slot)
		}
		return ef.LookupSymbol(libpf.SymbolName(relocSym))
	}

	offset := reloc.Addend
	if relocType == pfelf.RelDTPMOD64 {
		// The tls_index holds the module ID followed by the offset in the
		// TLS block, which is 0 for local-dynamic.
		if slot > ^libpf.Address(0)-8 {
			return nil, fmt.Errorf("invalid tls_index address %#x", slot)
		}
		blockOffset, err := ef.GetRemoteMemory().ReadUint64(slot + 8)
		if err != nil {
			return nil, fmt.Errorf("failed to read tls_index at 0x%x: %w", slot, err)
		}
		if blockOffset > math.MaxInt64 {
			return nil, fmt.Errorf("invalid TLS block offset %#x at slot %#x", blockOffset, slot)
		}
		offset = int64(blockOffset)
	}
	sum := offset + disp
	if sum < 0 || (disp < 0 && sum > offset) {
		return nil, fmt.Errorf("invalid TLS block offset %d + %d at slot %#x", offset, disp, slot)
	}
	// The name is only used in error messages.
	return &libpf.Symbol{
		Name:    libpf.SymbolName(fmt.Sprintf("TLS variable at slot %#x", slot)),
		Address: libpf.SymbolValue(sum),
		Info:    elf.ST_INFO(elf.STB_LOCAL, elf.STT_TLS),
		Shndx:   uint16(elf.SHN_ABS),
	}, nil
}
