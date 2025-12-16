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

	for {
		op, err := it.Step()
		if err != nil {
			break
		}
		if op.Op != x86asm.MOV {
			continue
		}
		mem, ok := op.Args[1].(x86asm.Mem)
		if !ok || mem.Segment != x86asm.FS {
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
		// or loaded from memory via RIP-relative addressing:
		// 0x000000000017e34c0 <+0>: 	mov    0x40b9af9(%rip),%rcx        # 589cfc0 <runtime.tlsg@@Base+0x589cfc0>
		// 0x000000000017e34c7 <+7>:	mov    %fs:(%rcx),%rax
		// The register system handles RIP-relative addressing transparently,
		// resolving it to a virtual memory address.
		actual := it.Regs.GetX86(mem.Base)
		if actual.Match(offset) {
			return int32(offset.CapturedValue()), nil
		}
		// If the register value is a memory reference, read from it
		addr := e.NewImmediateCapture("addr")
		if actual.Match(e.Mem8(addr)) {
			valueBytes, err := f.VirtualMemory(int64(addr.CapturedValue()), 8, 8)
			if err != nil {
				continue
			}
			// Read the 8-byte value as int64 (little-endian)
			value := int64(npsr.Uint64(valueBytes, 0))
			return int32(value), nil
		}
	}
	return -8, fmt.Errorf("symbol '%s': %w", symbolName, errDecodeSymbol)
}
