//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	npsr "go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
	"golang.org/x/arch/x86/x86asm"
)

// Most normal amd64 Go binaries use -8 as offset into TLS space for
// storing the current g but "static" binaries it ends up as -80. There
// may be dynamic relocating going on so just read it from a known
// symbol if possible.
func extractTLSGOffset(f *pfelf.File) (int32, error) {
	pclntab, err := elfunwindinfo.NewGopclntab(f)
	if err != nil {
		return 0, err
	}
	defer pclntab.Close()

	symbolName := "runtime.stackcheck"

	// Dump of assembler code for function runtime.stackcheck:
	// 0x0000000000470080 <+0>:     mov    %fs:0xfffffffffffffff8,%rax
	// Binaries built with -buildmode=pie have a different assembly code for stackcheck with 2 movs:
	//  0x00000000007ec320 <+0>:	mov    $0xfffffffffffffff8,%rcx
	//  0x00000000007ec327 <+7>:	mov    %fs:(%rcx),%rax
	// In some binaries offset is stored relative to RIP:
	// 0x000000000017e34c0 <+0>: 	mov    0x40b9af9(%rip),%rcx        # 589cfc0 <runtime.tlsg@@Base+0x589cfc0>
	// 0x000000000017e34c7 <+7>:	mov    %fs:(%rcx),%rax
	sym, err := pclntab.LookupSymbol(libpf.SymbolName(symbolName))
	if err != nil {
		return 0, err
	}

	sz := int(min(sym.Size, 128))
	code, err := f.VirtualMemory(int64(sym.Address), sz, sz)
	if err != nil {
		return 0, err
	}

	offset := e.NewImmediateCapture("offset")
	it := amd.NewInterpreterWithCode(code)
	it.CodeAddress = e.Imm(uint64(sym.Address))

	var prevOp x86asm.Inst

	for {
		op, err := it.Step()
		if err != nil {
			break
		}
		if op.Op != x86asm.MOV {
			prevOp = op
			continue
		}
		mem, ok := op.Args[1].(x86asm.Mem)
		if !ok || mem.Segment != x86asm.FS {
			prevOp = op
			continue
		}
		// If the base is 0, it means the offset is directly in the register:
		// 0x0000000000470080 <+0>:     mov    %fs:0xfffffffffffffff8,%rax
		if mem.Base == 0 {
			return int32(mem.Disp), nil
		}
		// Otherwise, the offset is in the register:
		// 0x00000000007ec320 <+0>:	mov    $0xfffffffffffffff8,%rcx
		// 0x00000000007ec327 <+7>:	mov    %fs:(%rcx),%rax
		// Check if the register value was set with an immediate value in a previous instruction
		// and if so, use that value as the offset.
		actual := it.Regs.GetX86(mem.Base)
		if actual.Match(offset) {
			return int32(offset.CapturedValue()), nil
		}
		// Handle RIP-relative addressing case:
		// 0x000000000017e34c0 <+0>: 	mov    0x40b9af9(%rip),%rcx        # 589cfc0 <runtime.tlsg@@Base+0x589cfc0>
		// 0x000000000017e34c7 <+7>:	mov    %fs:(%rcx),%rax
		// The previous instruction should be a RIP-relative MOV that loads into the current base register.
		if prevOp.Op == x86asm.MOV {
			if dst, ok := prevOp.Args[0].(x86asm.Reg); ok && dst == mem.Base {
				if prevMem, ok := prevOp.Args[1].(x86asm.Mem); ok && prevMem.Base == x86asm.RIP {
					// Calculate the address where the TLS offset is stored: RIP + displacement
					// Substract the length of the current operation to not account it twice when using it.PC().
					ripAddr := uint64(sym.Address) + uint64(it.PC()) - uint64(op.Len)
					addr := ripAddr + uint64(prevMem.Disp)

					valueBytes, err := f.VirtualMemory(int64(addr), 8, 8)
					if err != nil {
						continue
					}

					// Read the 8-byte value as int64 (little-endian)
					value := int64(npsr.Uint64(valueBytes, 0))
					return int32(value), nil
				}
			}
		}

		prevOp = op
	}
	return -8, fmt.Errorf("symbol '%s': %w", symbolName, errDecodeSymbol)
}
