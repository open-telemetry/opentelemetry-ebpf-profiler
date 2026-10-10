// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import (
	"debug/elf"
	"errors"
	"fmt"

	"golang.org/x/arch/arm64/arm64asm"
	"golang.org/x/arch/x86/x86asm"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func findJsDispatchTableOffset(ef *pfelf.File, syms relevantSymbols) (uint64, error) {
	sym := syms.JSDispatchTableAddress
	if sym == nil {
		return 0, errors.New("js_dispatch_table_address not found; can't analyze it to find js_dispatch_table_ offset")
	}
	// the most I've observed mattering is 80 bytes
	// and that was in debug mode; allow up to 256 just to be safe.
	sz := min(sym.Size, 256)
	code := make([]byte, sz)
	if _, err := ef.ReadAt(code, int64(sym.Address)); err != nil {
		return 0, fmt.Errorf("failed to read js_dispatch_table_address code: %w", err)
	}

	return decodeJsDispatchTableOffset(ef.Machine, code, uint64(sym.Address))
}

// decodeJsDispatchTableOffset runs js_dispatch_table_address(), whose code
// starts at addr, up to its first `ret`, and returns the offset in
// IsolateGroup that the return value was loaded from.
func decodeJsDispatchTableOffset(machine elf.Machine, code []byte, addr uint64) (uint64, error) {
	var retval expression.Expression
	switch machine {
	case elf.EM_AARCH64:
		it := arm.NewInterpreterWithCodeAt(code, expression.Imm(addr))
		_, err := it.LoopWithBreak(func(i arm64asm.Inst) bool {
			return i.Op == arm64asm.RET
		})
		if err != nil {
			return 0, err
		}
		retval = it.Regs.Get(arm.X0)
	case elf.EM_X86_64:
		it := amd.NewInterpreterWithCodeAt(code, expression.Imm(addr))
		_, err := it.LoopWithBreak(func(i x86asm.Inst) bool {
			return i.Op == x86asm.RET
		})
		if err != nil {
			return 0, err
		}
		retval = it.Regs.Get(amd.RAX)
	default:
		return 0, fmt.Errorf("unsupported arch %s", machine.String())
	}
	// The IsolateGroup pointer is loaded either directly from
	// default_isolate_group_ or through its GOT entry.
	slot := expression.NewImmediateCapture("slot")
	offset := expression.NewImmediateCapture("offset")
	group := expression.Mem8(slot)
	if retval.Match(expression.Mem8(expression.Add(group, offset))) ||
		retval.Match(expression.Mem8(expression.Add(expression.Mem8(group), offset))) {
		return offset.CapturedValue(), nil
	}
	return 0, errors.New("failed to find js_dispatch_table_ field offset")
}
