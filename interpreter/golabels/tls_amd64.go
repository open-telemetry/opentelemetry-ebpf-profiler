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
	// Offset is stored relative to RIP:
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
	pc := 0
	// Register -> loaded TLS offset from RIP-relative memory
	ripRelLoads := make(map[x86asm.Reg]int64)

	for {
		op, err := it.Step()
		if err != nil {
			break
		}
		curAddr := int64(sym.Address) + int64(pc)

		if op.Op == x86asm.MOV {
			// Handle FS:... cases
			if mem, ok := op.Args[1].(x86asm.Mem); ok && mem.Segment == x86asm.FS {
				// Direct offset in instruction
				if mem.Base == 0 {
					return int32(mem.Disp), nil
				}
				// Offset previously set via immediate into the base register
				actual := it.Regs.GetX86(mem.Base)
				if actual.Match(offset) {
					return int32(offset.CapturedValue()), nil
				}
				// RIP-relative case: previous MOV loaded the TLS offset into this register
				if v, ok := ripRelLoads[mem.Base]; ok {
					return int32(v), nil
				}
			}

			// RIP-relative load: mov disp(%rip), %reg
			if mem, ok := op.Args[1].(x86asm.Mem); ok && mem.Base == x86asm.RIP {
				if dst, ok := op.Args[0].(x86asm.Reg); ok {
					instrLen := op.Len
					target := curAddr + int64(mem.Disp) + int64(instrLen)

					// Read 8-byte TLS value from target address
					b, err := f.VirtualMemory(target, 8, 8)
					if err == nil && len(b) >= 8 {
						u := uint64(b[0]) |
							uint64(b[1])<<8 |
							uint64(b[2])<<16 |
							uint64(b[3])<<24 |
							uint64(b[4])<<32 |
							uint64(b[5])<<40 |
							uint64(b[6])<<48 |
							uint64(b[7])<<56
						ripRelLoads[dst] = int64(u)
					}
				}
			}
		}

		if op.Len != 0 {
			pc += op.Len
		} else {
			pc += 7 // avoid infinite loop
		}
	}
	return -8, fmt.Errorf("symbol '%s': %w", symbolName, errDecodeSymbol)
}
