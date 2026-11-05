// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls // import "go.opentelemetry.io/ebpf-profiler/tls"

import (
	"encoding/binary"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const instSz = 4

// staticResolverBody is the entire static TLSDESC resolver:
//
//	f9400400  ldr x0, [x0, #8]
//	d65f03c0  ret
//
// glibc, musl, bionic and uClibc-ng all write this body in hand-written
// assembly, so no build flag moves it. glibc's _dl_tlsdesc_return_lazy
// prepends an "ldar xzr, [x0]" barrier and does not match, but nothing
// installs it: elf_machine_lazy_rel relocates TLSDESC eagerly.
var staticResolverBody = [...]uint32{0xf9400400, 0xd65f03c0}

// maxLandingPads bounds the hints tolerated ahead of the body, and so the read
// size. glibc and bionic emit one when built for BTI, musl and uClibc-ng none.
// The spare is for a prologue hint we have not seen, and is safe because no
// hint touches x0.
const maxLandingPads = 2

const resolverCodeSize = (len(staticResolverBody) + maxLandingPads) * instSz

// The whole HINT encoding space, bits 11:5 (CRm:op2) holding the immediate.
// Nothing in it writes x0, the bti variants glibc and bionic land on and the
// PAC hints included, so tolerating any of them ahead of the body is safe.
const (
	hintMask = 0xfffff01f
	hintBits = 0xd503201f
)

func isHint(w uint32) bool { return w&hintMask == hintBits }

// tlsdescReturnsArg reports whether the TLSDESC resolver at addr hands back the
// descriptor's argument word unchanged, which is what makes that argument a
// TP-relative offset: the aarch64 call sequence adds the thread pointer to
// whatever the resolver returns.
//
// Matched by code because loaders ship stripped and these symbols are hidden.
// An unreadable resolver is an error, not a false: the word is relocated, so
// it points at real loader text.
func tlsdescReturnsArg(rm remotememory.RemoteMemory, addr libpf.Address) (bool, error) {
	var code [resolverCodeSize]byte
	if err := rm.Read(addr, code[:]); err != nil {
		return false, err
	}
	word := func(i int) uint32 { return binary.LittleEndian.Uint32(code[i*instSz:]) }

	i := 0
	for i < maxLandingPads && isHint(word(i)) {
		i++
	}
	for j, want := range staticResolverBody {
		if word(i+j) != want {
			return false, nil
		}
	}
	return true, nil
}
