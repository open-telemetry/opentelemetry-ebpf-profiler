// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf"

import (
	"debug/elf"
	"fmt"
	"math"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func roundUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}

// StaticTLSOffset computes the thread-pointer-relative offset of a local-exec TLS
// variable defined in this executable's static TLS block, where sym.Address is
// the symbol's offset within the PT_TLS image. The result is negative on variant
// II architectures, returned as a uint64 underflow.
func (f *File) StaticTLSOffset(sym *libpf.Symbol) (uint64, error) {
	tlsProg := f.ProgByType(elf.PT_TLS)
	if tlsProg == nil {
		return 0, fmt.Errorf("failed to locate TLS segment")
	}
	// Bounded by what a descriptor can hold anyway (see
	// support.NewStaticTLSVarInfo), which also keeps the rounding below from
	// wrapping.
	if tlsProg.Memsz > math.MaxInt32 {
		return 0, fmt.Errorf("implausible TLS segment size %d", tlsProg.Memsz)
	}
	align := max(tlsProg.Align, 1)
	if align&(align-1) != 0 {
		return 0, fmt.Errorf("TLS segment alignment %d is not a power of two", align)
	}
	// A symbol claiming to sit outside the TLS image means a malformed PT_TLS:
	// the arithmetic below would turn it into a plausible-looking offset. Phrased
	// as a subtraction because the sum can wrap past the check.
	symAddr := uint64(sym.Address)
	if symAddr > tlsProg.Memsz || sym.Size > tlsProg.Memsz-symAddr {
		return 0, fmt.Errorf("TLS symbol at 0x%x size %d exceeds TLS segment size %d",
			sym.Address, sym.Size, tlsProg.Memsz)
	}

	// Both cases assume PT_TLS's p_vaddr is p_align-aligned, which linkers
	// normally emit. When it is not, glibc and musl shift the block by
	// different amounts, glibc by firstbyte = (-p_vaddr) & (align-1) and musl
	// by a rounding of image + size, and the mapping libc is unknown here, so
	// matching one would break the other.
	switch f.Machine {
	case elf.EM_AARCH64:
		// Variant I: the static TLS block sits above TP, at the first
		// align-aligned offset past a 16-byte reserved area (TCB on glibc,
		// GAP_ABOVE_TP on musl).
		return roundUp(16, align) + symAddr, nil
	case elf.EM_X86_64:
		// Variant II: the executable's TLS block sits immediately below TP, its
		// size rounded up to the block alignment.
		return symAddr - roundUp(tlsProg.Memsz, align), nil
	}
	return 0, fmt.Errorf("unsupported machine: %s", f.Machine)
}
