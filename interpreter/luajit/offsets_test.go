// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestX86LuaClose(t *testing.T) {
	testdata := []struct {
		name          string
		glRefExpected libpf.Address
		curLExpected  libpf.Address
		code          []byte
	}{
		{
			name:          "size-optimized-register-zero",
			glRefExpected: 0x10,
			curLExpected:  0x158,
			code: []byte{
				0x41, 0x55, //                               pushq   %r13
				0x4c, 0x8d, 0x2d, 0x3f, 0xd4, 0xff, 0xff, // leaq    -0x2bc1(%rip), %r13
				0x41, 0x54, //                               pushq   %r12
				0x41, 0xbc, 0x0a, 0x00, 0x00, 0x00, //       movl    $0xa, %r12d
				0x55,                   //                   pushq   %rbp
				0x53,                   //                   pushq   %rbx
				0x51,                   //                   pushq   %rcx
				0x48, 0x8b, 0x5f, 0x10, //                   movq    0x10(%rdi), %rbx
				0x48, 0x8b, 0xab, 0xc8, 0x00, 0x00, 0x00, // movq    0xc8(%rbx), %rbp
				0x48, 0x89, 0xef, // movq    %rbp, %rdi
				0xe8, 0x6e, 0x17, 0x00, 0x00, // callq   0x175f0 <luaJIT_profile_stop>
				0x31, 0xf6, // xorl    %esi, %esi
				0x48, 0x89, 0xef, // movq    %rbp, %rdi
				0x48, 0x89, 0xb3, 0x58, 0x01, 0x00, 0x00, // movq    %rsi, 0x158(%rbx)
			},
		},
		{
			// The canonical form per lua_close's source uses `movq $0x0, OFS(reg)`
			// directly instead of zeroing a register first.
			name:          "immediate-zero-store",
			glRefExpected: 0x10,
			curLExpected:  0x170,
			code: []byte{
				0x48, 0x8b, 0x5f, 0x10, //                                     movq $0x10(%rdi), %rbx
				0x48, 0xc7, 0x83, 0x70, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movq $0x0, 0x170(%rbx)
			},
		},
		{
			// endbr64 prefix - the asm/amd interpreter skips it transparently
			// so we no longer need an explicit SkipEndBranch call.
			name:          "endbr64-prefix",
			glRefExpected: 0x10,
			curLExpected:  0x158,
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, //                                     endbr64
				0x48, 0x8b, 0x5f, 0x10, //                                     movq 0x10(%rdi), %rbx
				0x48, 0xc7, 0x83, 0x58, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movq $0x0, 0x158(%rbx)
			},
		},
		{
			// Resilience case the old extractor would miss on two counts:
			//   1. R8 was zeroed via `xor %r8d, %r8d`; sameReg() only
			//      whitelisted EAX/ECX/EDX/EBX/ESI so R8/R8D would not match.
			//   2. The glref load is *not* directly from %rdi - the compiler
			//      first parked L in %rax, then loaded G via %rax. The old
			//      code required a1.Base == x86asm.RDI on the load.
			// Symbolic tracking handles both for free.
			name:          "r8-zero-and-rdi-mov-chain",
			glRefExpected: 0x10,
			curLExpected:  0x158,
			code: []byte{
				0x45, 0x31, 0xc0, //                                     xorl %r8d, %r8d
				0x48, 0x89, 0xf8, //                                     movq %rdi, %rax
				0x48, 0x8b, 0x58, 0x10, //                               movq 0x10(%rax), %rbx
				0x4c, 0x89, 0x83, 0x58, 0x01, 0x00, 0x00, //             movq %r8, 0x158(%rbx)
			},
		},
	}

	for _, test := range testdata {
		t.Run(test.name, func(t *testing.T) {
			x := x86Extractor{}
			glref, curL, err := x.findOffsetsFromLuaClose(test.code)
			require.NoError(t, err)
			require.Equal(t, test.glRefExpected, glref)
			require.Equal(t, test.curLExpected, curL)
		})
	}
}

func TestX86Checktrace(t *testing.T) {
	testdata := []struct {
		name     string
		expected libpf.Address
		code     []byte
	}{
		{
			// Canonical jit_checktrace per the disasm comment in
			// extractor_x86.go: L (%rdi) is parked in %rbx, G is loaded as
			// L->glref via 0x10(%rbx), then the J->traces load is at
			// 0x430(%rdx).
			name:     "canonical",
			expected: 0x430,
			code: []byte{
				0x48, 0x89, 0xfb, //                         mov  %rdi, %rbx
				0x48, 0x8b, 0x53, 0x10, //                   mov  0x10(%rbx), %rdx
				0x48, 0x8b, 0x92, 0x30, 0x04, 0x00, 0x00, // mov  0x430(%rdx), %rdx
			},
		},
		{
			// SUB-shifted register: some builds apply a constant adjustment to
			// G's register before the final load. Old extractor accumulated
			// this manually; symbolic interpreter folds (-0xc + 0x43c) into
			// 0x430 via Add canonicalization. Recently broke in the wild
			// (#99ec409).
			name:     "sub-adjusted",
			expected: 0x430,
			code: []byte{
				0x48, 0x8b, 0x57, 0x10, //                   mov  0x10(%rdi), %rdx
				0x48, 0x83, 0xea, 0x0c, //                   sub  $0xc, %rdx
				0x48, 0x8b, 0x92, 0x3c, 0x04, 0x00, 0x00, // mov  0x43c(%rdx), %rdx
			},
		},
		{
			// ADD-shifted register: symmetric to the SUB case. (0xc + 0x424) = 0x430.
			name:     "add-adjusted",
			expected: 0x430,
			code: []byte{
				0x48, 0x8b, 0x57, 0x10, //                   mov  0x10(%rdi), %rdx
				0x48, 0x83, 0xc2, 0x0c, //                   add  $0xc, %rdx
				0x48, 0x8b, 0x92, 0x24, 0x04, 0x00, 0x00, // mov  0x424(%rdx), %rdx
			},
		},
		{
			// Resilience case: G is moved to an intermediate register before
			// the final load. Old extractor required the load's base to be
			// the same register that received the 0x10(L) load directly;
			// symbolic tracking propagates the value through the chain.
			name:     "mov-chain-through-intermediate-reg",
			expected: 0x430,
			code: []byte{
				0x48, 0x8b, 0x57, 0x10, //                   mov  0x10(%rdi), %rdx
				0x48, 0x89, 0xd6, //                         mov  %rdx, %rsi
				0x48, 0x8b, 0x8e, 0x30, 0x04, 0x00, 0x00, // mov  0x430(%rsi), %rcx
			},
		},
	}

	for _, tc := range testdata {
		t.Run(tc.name, func(t *testing.T) {
			x := x86Extractor{}
			got, err := x.findG2TracesOffsetFromChecktrace(tc.code)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestX86LjDispatchUpdateAddr(t *testing.T) {
	testdata := []struct {
		name     string
		baseAddr libpf.Address
		expected libpf.Address
		code     []byte
	}{
		{
			// Canonical: stash L in callee-saved %rbx, then load G into %rdi
			// for the lj_dispatch_update call. CALL targets baseAddr+12+0xff4
			// = 0x1000.
			name:     "canonical-via-rbx",
			baseAddr: 0,
			expected: 0x1000,
			code: []byte{
				0x48, 0x89, 0xfb, //                      mov  %rdi, %rbx
				0x48, 0x8b, 0x7b, 0x10, //                mov  0x10(%rbx), %rdi
				0xe8, 0xf4, 0x0f, 0x00, 0x00, //          call 0x1000
			},
		},
		{
			// Resilience case: the compiler loads G straight into %rdi without
			// first parking L in a separate register. The old extractor's
			// Lreg-then-load pattern required the stash; symbolic tracking
			// follows L's provenance through the self-overwrite of %rdi.
			name:     "direct-rdi-self-overwrite",
			baseAddr: 0,
			expected: 0x1000,
			code: []byte{
				0x48, 0x8b, 0x7f, 0x10, //                mov  0x10(%rdi), %rdi
				0xe8, 0xf7, 0x0f, 0x00, 0x00, //          call 0x1000
			},
		},
		{
			// Earlier calls in the prologue do not have G in %rdi and must be
			// skipped over without consuming the result.
			name:     "skip-prologue-call",
			baseAddr: 0,
			expected: 0x1000,
			code: []byte{
				0x48, 0x89, 0xfb, //                      mov  %rdi, %rbx
				0xe8, 0xf8, 0x04, 0x00, 0x00, //          call 0x500 (not dispatch_update)
				0x48, 0x8b, 0x7b, 0x10, //                mov  0x10(%rbx), %rdi
				0xe8, 0xef, 0x0f, 0x00, 0x00, //          call 0x1000 (dispatch_update)
			},
		},
	}

	for _, tc := range testdata {
		t.Run(tc.name, func(t *testing.T) {
			x := x86Extractor{}
			got, err := x.findLjDispatchUpdateAddr(tc.code, tc.baseAddr)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestX86RipRelativeLea2ndArgTo2ndCall(t *testing.T) {
	// Two LEA-CALL pairs; both CALLs target 0x1000. After the 1st call's LEA
	// RSI = 0x500; after the 2nd's RSI = 0xa00. The function should return
	// 0xa00 (RSI's value at the 2nd matching CALL).
	code := []byte{
		0x48, 0x8d, 0x35, 0xf9, 0x04, 0x00, 0x00, // lea  0x4f9(%rip), %rsi  ; RSI = 0+7+0x4f9 = 0x500
		0xe8, 0xf4, 0x0f, 0x00, 0x00, //             call 0x1000             ; target=0+12+0xff4
		0x48, 0x8d, 0x35, 0xed, 0x09, 0x00, 0x00, // lea  0x9ed(%rip), %rsi  ; RSI = 0+19+0x9ed = 0xa00
		0xe8, 0xe8, 0x0f, 0x00, 0x00, //             call 0x1000             ; target=0+24+0xfe8
	}
	x := x86Extractor{}
	got, err := x.find2ndArgTo2ndPushClosureCall(code, 0, 0x1000)
	require.NoError(t, err)
	require.Equal(t, libpf.Address(0xa00), got)
}

func TestX86Find4thArgToLibRegCall(t *testing.T) {
	testdata := []struct {
		name     string
		expected libpf.Address
		code     []byte
	}{
		{
			// Canonical luaopen_jit_util: lea $rip-rel, %rcx; ...; call lj_lib_register.
			// LEA at pos 4 (7 bytes), so RCX = 0 + 11 + 0xd21f5 = 0xd2200.
			name:     "lea-rip-relative",
			expected: 0xd2200,
			code: []byte{
				0x48, 0x83, 0xec, 0x08, //                   sub  $0x8, %rsp
				0x48, 0x8d, 0x0d, 0xf5, 0x21, 0x0d, 0x00, // lea  0xd21f5(%rip), %rcx
				0xe8, 0xf0, 0xff, 0x01, 0x00, //             call (target irrelevant)
			},
		},
		{
			// Some compilers materialize the 4th arg via `mov $imm, %ecx`.
			name:     "mov-immediate",
			expected: 0x1234,
			code: []byte{
				0xb9, 0x34, 0x12, 0x00, 0x00, //             mov  $0x1234, %ecx
				0xe8, 0xfb, 0x1f, 0x00, 0x00, //             call (target irrelevant)
			},
		},
	}

	for _, tc := range testdata {
		t.Run(tc.name, func(t *testing.T) {
			x := x86Extractor{}
			got, err := x.find4thArgToLibRegCall(tc.code, 0)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestX86Find3rdArgToLibPreregCall(t *testing.T) {
	// Construct a minimal AABA call sequence (A=0x1000, B=0x2000) followed by
	// 3 more CALLs, with `lea $rip-rel, %rdx` immediately before the 3rd.
	// AABA section occupies bytes 0-19; the post-AABA interpreter section
	// runs from byte 20 onward with CodeAddress=20:
	//   pos 20-24: CALL (target irrelevant - 1st post-AABA)
	//   pos 25-29: CALL                                (2nd)
	//   pos 30-36: LEA  0x3fdb(%rip), %rdx  -> RDX = 20 + 17 + 0x3fdb = 0x4000
	//   pos 37-41: CALL                                (3rd - read RDX here)
	code := []byte{
		// AABA: A, A, B, A (A=0x1000, B=0x2000), each call is 5 bytes
		0xe8, 0xfb, 0x0f, 0x00, 0x00, //                 call 0x1000   (A, pos 0)
		0xe8, 0xf6, 0x0f, 0x00, 0x00, //                 call 0x1000   (A, pos 5)
		0xe8, 0xf1, 0x1f, 0x00, 0x00, //                 call 0x2000   (B, pos 10)
		0xe8, 0xec, 0x0f, 0x00, 0x00, //                 call 0x1000   (A, pos 15) -> ip=20

		// Post-AABA section interpreted with CodeAddress=20.
		0xe8, 0x00, 0x00, 0x00, 0x00, //                 call (1st post-AABA, pos 20)
		0xe8, 0x00, 0x00, 0x00, 0x00, //                 call (2nd post-AABA, pos 25)
		0x48, 0x8d, 0x15, 0xdb, 0x3f, 0x00, 0x00, //     lea  0x3fdb(%rip), %rdx
		0xe8, 0x00, 0x00, 0x00, 0x00, //                 call (3rd post-AABA, pos 37)
	}
	x := x86Extractor{}
	got, err := x.find3rdArgToLibPreregCall(code, 0)
	require.NoError(t, err)
	require.Equal(t, libpf.Address(0x4000), got)
}
