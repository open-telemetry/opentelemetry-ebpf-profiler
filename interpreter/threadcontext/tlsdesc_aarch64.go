// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package threadcontext // import "go.opentelemetry.io/ebpf-profiler/interpreter/threadcontext"

import (
	"golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// resolverCodeSize bounds how much of a resolver is decoded. The static ones
// are two instructions, three with a BTI landing pad.
const resolverCodeSize = 6 * arm.InstSz

// resolverModeledOp reports whether the interpreter accounts for op's effect on
// the registers. Stepping over an unmodeled instruction leaves stale values
// behind, and a stale "x0 holds the argument" is exactly the false positive
// this check must not produce.
//
// ADD and SUB are deliberately absent despite the interpreter naming them: it
// drops their register-register form, whose third operand is a
// RegExtshiftAmount it does not decode, and so leaves the destination stale.
// Both real dynamic resolvers end that way, musl's __tlsdesc_dynamic on
// "add x0, x1, x2" and glibc's _dl_tlsdesc_undefweak on "sub x0, x0, x1". A
// static resolver needs neither.
func resolverModeledOp(op arm64asm.Op) bool {
	switch op {
	// BTI landing pad and PAC hints, all no-ops here.
	case arm64asm.HINT, arm64asm.NOP:
		return true
	case arm64asm.LDR, arm64asm.MOV, arm64asm.RET:
		return true
	}
	return false
}

// tlsdescReturnsArg reports whether the TLSDESC resolver at addr hands back the
// descriptor's argument word unchanged.
//
// The aarch64 call sequence adds the thread pointer to whatever the resolver
// returns, so returning the argument verbatim is what *makes* that argument a
// TP-relative offset: static TLS. It is a property of the code rather than of a
// particular libc, hence decoding it instead of matching known resolver
// addresses -- which is also the only option available, since loaders ship
// stripped and _dl_tlsdesc_return is hidden, so there is no symbol to match.
//
// glibc's _dl_tlsdesc_return and musl's __tlsdesc_static are both
// "[bti c;] ldr x0, [x0, #8]; ret". Anything else, including an unreadable or
// undecodable resolver, reports false and leaves the caller to fall back to
// inspecting the argument itself.
func tlsdescReturnsArg(rm remotememory.RemoteMemory, addr libpf.Address) (bool, error) {
	code := make([]byte, resolverCodeSize)
	if err := rm.Read(addr, code); err != nil {
		if processInaccessible(err) {
			return false, err
		}
		return false, nil
	}

	it := arm.NewInterpreterWithCode(code)
	it.CodeAddress = expression.Imm(uint64(addr))
	// Stop at the first unmodeled instruction or at the RET. Landing anywhere
	// but the RET means the decode never reached the resolver's return.
	last, err := it.LoopWithBreak(func(i arm64asm.Inst) bool {
		return !resolverModeledOp(i.Op) || i.Op == arm64asm.RET
	})
	if err != nil || last.Op != arm64asm.RET {
		return false, nil
	}

	// On entry x0 points at the descriptor, whose second word is the argument.
	arg := expression.Mem8(expression.Add(
		expression.Named(arm.X0.String()), expression.Imm(8)))
	return it.Regs.Get(arm.X0).Match(arg), nil
}
