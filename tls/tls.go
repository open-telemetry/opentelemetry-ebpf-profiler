// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package tls locates a thread-local variable of a running process, given the
// ELF that defines it. Resolve classifies how the variable is accessed, once per
// file, and Locate turns that into a descriptor eBPF can follow, once per process.
package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// VarInfo locates a resolved thread-local variable. Alias of the eBPF struct,
// following libc.DTVInfo and stackdeltatypes.UnwindInfo.
type VarInfo = support.TLSVarInfo

var (
	// ErrUnsupportedModel means no access model could be determined for the
	// symbol. Callers with a fallback path treat this as "not available here"
	// rather than as a malformed ELF.
	ErrUnsupportedModel = errors.New("unsupported TLS access model")
	// ErrUnresolved means the dynamic loader has not applied the relocation the
	// variable is accessed through, which is distinct from failing to read it.
	ErrUnresolved = errors.New("TLS relocation not applied")
)

// Var is a thread-local variable whose access model is known, ready to be
// located in any process that maps the ELF it came from.
type Var struct {
	access accessModel
	// elfAddr is the (unbiased) ELF address of the TLS descriptor or GOT slot
	// used by the initial-exec, tlsdesc and gnu-dynamic access models.
	elfAddr libpf.Address
	// addend is the static part of the offset, added to whatever the relocation
	// resolves at runtime. It is the whole answer for local-exec, where nothing
	// is read, and zero wherever the relocation resolves the offset in full.
	addend uint64
	// variant is the TLS layout the target architecture prescribes, which is
	// what tells a genuinely unresolved GOT slot from a legitimately zero
	// TP-relative offset (see the accessInitialExec case in Locate).
	variant tlsVariant
}

type tlsVariant uint8

const (
	// variantI puts the static TLS block above the thread pointer, so both a
	// TP offset and a tls_index pointer are positive. aarch64.
	variantI tlsVariant = iota + 1
	// variantII puts it below, so a real TP offset is always negative. x86-64.
	variantII
)

func (t tlsVariant) String() string {
	switch t {
	case variantI:
		return "variant I"
	case variantII:
		return "variant II"
	default:
		return "variant unset"
	}
}

// pfelf.File.StaticTLSOffset splits the same way and must agree with this.
func tlsVariantOf(machine elf.Machine) (tlsVariant, error) {
	switch machine {
	case elf.EM_AARCH64:
		return variantI, nil
	case elf.EM_X86_64:
		return variantII, nil
	}
	return 0, fmt.Errorf("%w: machine %s", ErrUnsupportedModel, machine)
}

func (v Var) String() string {
	return fmt.Sprintf("%v %v elfAddr=0x%x addend=0x%x",
		v.access, v.variant, v.elfAddr, v.addend)
}

// Locate resolves the variable in the process rm reads, mapped at bias.
//
// The returned descriptor is resolved for static TLS, and awaiting its DTV
// layout for dynamic TLS (support.TLSVarInfo.SetDTVInfo completes it).
func (v Var) Locate(rm remotememory.RemoteMemory, bias libpf.Address) (VarInfo, error) {
	switch v.access {
	case accessLocalExec:
		return support.NewStaticTLSVarInfo(v.addend)

	case accessInitialExec:
		// The GOT slot holds the variable's TP-relative offset directly.
		got, err := rm.ReadUint64(bias + v.elfAddr)
		if err != nil {
			return VarInfo{}, err
		}
		// On x86-64 (TLS variant II, block below TP) a real offset can never
		// be 0: the block's own size keeps it strictly negative. On aarch64
		// (variant I, block above TP) 0 is ambiguous: musl's loader reserves
		// its 16-byte GAP_ABOVE_TP for the executable's own block only, so
		// without PT_TLS in the executable the first library's block starts at
		// TP+0. glibc's 16-byte TCB always occupies TP..TP+16, so its block
		// never starts before TP+16 (see pfelf.File.StaticTLSOffset). aarch64
		// accepts 0 here, trading away detection of the unresolved-at-startup
		// case.
		if got == 0 && v.variant == variantII {
			return VarInfo{}, fmt.Errorf("%w: TLS GOT slot", ErrUnresolved)
		}
		return support.NewStaticTLSVarInfo(got + v.addend)

	case accessGeneralDynamic:
		// The GOT holds a tls_index {module_id, offset} pair.
		moduleID, offset, err := readUint64Pair(rm, bias+v.elfAddr)
		if err != nil {
			return VarInfo{}, err
		}
		return support.NewDynamicTLSVarInfo(moduleID, offset+v.addend)

	case accessLocalDynamic:
		// The GOT holds the module_id. The in-module offset is the symbol value.
		moduleID, err := rm.ReadUint64(bias + v.elfAddr)
		if err != nil {
			return VarInfo{}, err
		}
		return support.NewDynamicTLSVarInfo(moduleID, v.addend)

	case accessTLSDesc:
		// The descriptor's first word is the resolver function pointer, set to
		// a non-null address as soon as the dynamic linker processes the
		// relocation. Unlike the second word, it can never legitimately be
		// 0, making it the reliable "not yet relocated" signal.
		//
		// The argument word can't be used for that instead: musl's static
		// resolver stores a real TP-relative offset there, and that offset is
		// 0 for the first library's block in an executable without PT_TLS
		// (see the accessInitialExec case above).
		resolver, arg, err := readUint64Pair(rm, bias+v.elfAddr)
		if err != nil {
			return VarInfo{}, err
		}
		if resolver == 0 {
			return VarInfo{}, fmt.Errorf("%w: TLSDESC descriptor", ErrUnresolved)
		}
		return v.locateTLSDesc(rm, resolver, arg)

	default:
		return VarInfo{}, fmt.Errorf("%w: %v", ErrUnsupportedModel, v.access)
	}
}

// locateTLSDesc resolves a relocated TLS descriptor whose argument is either a
// TP-relative offset (static TLS) or a pointer to a tls_index (dynamic TLS).
func (v Var) locateTLSDesc(rm remotememory.RemoteMemory, resolver, arg uint64,
) (VarInfo, error) {
	switch v.variant {
	case variantII:
		// The block sits below TP, so a static offset is always negative and a
		// tls_index pointer never is.
		if int64(arg) < 0 {
			return support.NewStaticTLSVarInfo(arg + v.addend)
		}
		ti, err := derefTLSIndex(rm, arg)
		if err != nil {
			return VarInfo{}, fmt.Errorf("TLSDESC argument %#x is neither a negative "+
				"TP offset nor a tls_index: %w", arg, err)
		}
		return support.NewDynamicTLSVarInfo(ti.moduleID, ti.offset+v.addend)

	case variantI:
		// The block sits above TP, so both forms (pointer and offset) are positive.
		// Use magnitude as a first free discriminant: under minUserAddr it cannot
		// be an allocation, which spares the resolver read for the common small
		// TP offset.
		if arg < minUserAddr {
			return support.NewStaticTLSVarInfo(arg + v.addend)
		}

		// Otherwise ask the resolver: one that returns the argument unchanged
		// is what makes that argument a TP-relative offset.
		static, err := tlsdescReturnsArg(rm, libpf.Address(resolver))
		if err != nil {
			return VarInfo{}, err
		}
		if static {
			return support.NewStaticTLSVarInfo(arg + v.addend)
		}

		// No fallback to a static offset here: it would turn a failed read
		// into an address.
		ti, err := derefTLSIndex(rm, arg)
		if err != nil {
			return VarInfo{}, fmt.Errorf("TLSDESC argument %#x is not a tls_index "+
				"and resolver %#x is not the static form: %w", arg, resolver, err)
		}
		return support.NewDynamicTLSVarInfo(ti.moduleID, ti.offset+v.addend)
	}
	return VarInfo{}, fmt.Errorf("%w: TLS variant unset", ErrUnsupportedModel)
}

// readUint64Pair reads two adjacent 64-bit values in a single remote read.
func readUint64Pair(rm remotememory.RemoteMemory, addr libpf.Address) (uint64, uint64, error) {
	var buf [16]byte
	if err := rm.Read(addr, buf[:]); err != nil {
		return 0, 0, err
	}
	return binary.LittleEndian.Uint64(buf[:8]), binary.LittleEndian.Uint64(buf[8:]), nil
}

// minUserAddr bounds from below every address a loader can allocate a
// tls_index at, so an argument under it is an offset rather than a pointer.
// Both the common distro mmap_min_addr and, well above it, the lowest brk a
// real executable leaves for malloc.
const minUserAddr = 0x10000

// tlsIndex is the {module, offset} pair a dynamic TLS descriptor's argument
// points at. glibc (tlsdesc_dynamic_arg) and musl both start that block with it.
type tlsIndex struct {
	moduleID uint64
	offset   uint64
}

// derefTLSIndex reads the tls_index addr points at, erroring when it holds no
// plausible one. Callers reach it only once the argument cannot be an offset,
// so "not a tls_index" is a broken descriptor, not a classification.
func derefTLSIndex(rm remotememory.RemoteMemory, addr uint64) (tlsIndex, error) {
	moduleID, offset, err := readUint64Pair(rm, libpf.Address(addr))
	if err != nil {
		return tlsIndex{}, err
	}
	// Same module bound NewDynamicTLSVarInfo enforces, checked here to name
	// the address the pair came from.
	if moduleID == 0 || moduleID > support.MaxTLSModuleID {
		return tlsIndex{}, fmt.Errorf("implausible TLS module ID %d at %#x", moduleID, addr)
	}
	return tlsIndex{moduleID: moduleID, offset: offset}, nil
}
