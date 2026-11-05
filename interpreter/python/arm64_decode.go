// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python // import "go.opentelemetry.io/ebpf-profiler/interpreter/python"

import (
	aa "golang.org/x/arch/arm64/arm64asm"

	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// decodeStubArgumentARM64 disassembles arm64 code and decodes the assumed value
// of requested argument.
func decodeStubArgumentARM64(code []byte, pc uint64,
	addrBase libpf.SymbolValue) libpf.SymbolValue {

	i := arm.NewInterpreterWithCodeAt(code, e.Imm(pc))
	_, err := i.LoopWithBreak(func(op aa.Inst) bool {
		return op.Op == aa.B || op.Op == aa.BR || op.Op == aa.BL
	})
	if err != nil {
		return libpf.SymbolValueInvalid
	}
	r := i.Regs.Get(arm.X0)
	res := e.NewImmediateCapture("res")

	expected := e.ZeroExtend(
		e.Mem(res, 8),
		32,
	)
	if r.Match(expected) {
		return libpf.SymbolValue(res.CapturedValue())
	}
	expected = e.Add(
		e.Mem(
			e.NewImmediateCapture("ptr"),
			8,
		),
		res,
	)
	if r.Match(expected) {
		return libpf.SymbolValue(res.CapturedValue()) + addrBase
	}
	expected = e.ZeroExtend(
		e.Mem(
			e.Add(
				e.Mem(
					e.NewImmediateCapture("ptr"),
					8,
				),
				res,
			),
			8,
		),
		32)
	if r.Match(expected) {
		return libpf.SymbolValue(res.CapturedValue()) + addrBase
	}
	if r.Match(res) {
		return libpf.SymbolValue(res.CapturedValue())
	}
	return libpf.SymbolValueInvalid
}
