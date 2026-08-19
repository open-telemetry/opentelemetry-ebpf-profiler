// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package arm

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/asm/expression"
	"golang.org/x/arch/arm64/arm64asm"
)

// TestLuaOffsets is based on armExtractor.findG2TracesOffsetFromChecktrace, which
// is currently only available in Parca's fork, but is in the process of being upstreamed;
// until then, it's good to have it as a test of the arm interpreter. This exercises loads,
// adds, and movs.
//
// This function accesses `L->g->J.sztraces`, where `g` is at offset 0x10
// in the object pointer to by `L`, which is the first argument to the
// function; we are interested in finding the offset of `sztraces` in the
// object pointed to by `g`. Thus we must find the offset of the first
// load from a pointer that was itself loaded from offset 0x10 from the first argument.
//
// To make thing slightly more complicated, the first argument has been moved out of x0 by
// the time we read it, and the offset is computed in two steps (the `add x2, x2, #0x2a8` at 0x5dcb8 below,
// and the `ldr x0, [x2, #0x174]` at 0x5dcbc. Thus the answer should be 0x2a8 + 0x174 = 0x41c.
func TestLuaOffsets(t *testing.T) {
	// 0x5dc98: stp x19, x30, [sp, #-0x10]!
	// 0x5dc9c: mov w1, #1
	// 0x5dca0: mov x19, x0
	// 0x5dca4: bl #0x52e70 ; lj_lib_checkint+0
	// 0x5dca8: cbz w0, #0x5dcd8 ; jit_checktrace+0x40
	// 0x5dcac: ldr x2, [x19, #0x10]
	// 0x5dcb0: mov w1, w0
	// 0x5dcb4: mov x0, #0
	// 0x5dcb8: add x2, x2, #0x2a8
	// 0x5dcbc: ldr w3, [x2, #0x174]
	// 0x5dcc0: cmp w3, w1
	// 0x5dcc4: b.ls #0x5dcd0 ; jit_checktrace+0x38
	// 0x5dcc8: ldr x0, [x2, #0x168]
	// 0x5dccc: ldr x0, [x0, w1, uxtw #3]
	// 0x5dcd0: ldp x19, x30, [sp], #0x10
	// 0x5dcd4: ret
	// 0x5dcd8: mov x0, #0
	// 0x5dcdc: ldp x19, x30, [sp], #0x10
	// 0x5dce0: ret
	code := []byte{
		0xf3, 0x7b, 0xbf, 0xa9, 0x21, 0x00, 0x80, 0x52, 0xf3, 0x03, 0x00, 0xaa,
		0x73, 0xd4, 0xff, 0x97, 0x80, 0x01, 0x00, 0x34, 0x62, 0x0a, 0x40, 0xf9,
		0xe1, 0x03, 0x00, 0x2a, 0x00, 0x00, 0x80, 0xd2, 0x42, 0xa0, 0x0a, 0x91,
		0x43, 0x74, 0x41, 0xb9, 0x7f, 0x00, 0x01, 0x6b, 0x69, 0x00, 0x00, 0x54,
		0x40, 0xb4, 0x40, 0xf9, 0x00, 0x58, 0x61, 0xf8, 0xf3, 0x7b, 0xc1, 0xa8,
		0xc0, 0x03, 0x5f, 0xd6, 0x00, 0x00, 0x80, 0xd2, 0xf3, 0x7b, 0xc1, 0xa8,
		0xc0, 0x03, 0x5f, 0xd6,
	}
	it := NewInterpreterWithCode(code)
	// e.g.: `ldr x2, [x19, #0x10]`, where `x19` came from `mov x19, x0`
	gLoad := expression.Mem8(expression.Add(expression.Named("X0"), expression.Imm(0x10)))
	// e.g.: `ldr w3, [x2, #0x174]` or `ldr x2, [x2, #0x168]`,
	// where `x2` is ultimately derived from L->g (usually an
	// offset will have already been applied, e.g. `add x2, x2,
	// #0x2e0`, which the interpreter handles transparently.)
	g2traces := expression.NewImmediateCapture("g2traces")
	jFieldLoad := expression.Mem8(expression.Add(gLoad, g2traces))
	jShortFieldLoad := expression.ZeroExtend32(jFieldLoad)
	var result int
	_, err := it.LoopWithBreak(func(i arm64asm.Inst) bool {
		if i.Op == arm64asm.LDR {
			var e expression.Expression
			switch typed := i.Args[0].(type) {
			case arm64asm.Reg:
				e = it.Regs.GetArm(typed)
			case arm64asm.RegSP:
				e = it.Regs.GetArmSP(typed)
			}
			if e != nil && (e.Match(jFieldLoad) ||
				e.Match(jShortFieldLoad)) {
				result = int(g2traces.CapturedValue())
				return true
			}
		}
		return false
	})
	require.NoError(t, err)
	require.Equal(t, 0x41C, result)
}
