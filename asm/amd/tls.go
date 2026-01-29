// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package amd // import "go.opentelemetry.io/ebpf-profiler/asm/amd"

import (
	"fmt"

	e "go.opentelemetry.io/ebpf-profiler/asm/expression"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	npsr "go.opentelemetry.io/ebpf-profiler/nopanicslicereader"
	"golang.org/x/arch/x86/x86asm"
)

// ExtractFSOffsetFromCode scans through x86_64 assembly code looking for MOV instructions
// that access Thread Local Storage (TLS) via the FS segment register.
// It handles three common patterns:
//  1. Direct FS-relative addressing: MOV reg, FS:[offset]
//  2. Register-based addressing: MOV $offset, reg; MOV reg, FS:(reg)
//  3. RIP-relative addressing: MOV 0x...(RIP), reg; MOV reg, FS:(reg)
//
// The function returns the TLS offset found, or an error if no valid pattern is detected.
// For RIP-relative addressing, the file parameter can be provided to resolve memory references.
// If file is nil, RIP-relative memory dereferencing will be skipped.
func ExtractTLSOffset(code []byte, codeAddress uint64, file *pfelf.File) (int32, error) {
	offset := e.NewImmediateCapture("offset")
	it := NewInterpreterWithCode(code)
	it.CodeAddress = e.Imm(codeAddress)

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
		// Pattern 1: Direct FS-relative addressing
		// Example: MOV rax, FS:[0xfffffffffffffff8]
		if mem.Base == 0 {
			return int32(mem.Disp), nil
		}
		// Pattern 2 & 3: Register-based or RIP-relative addressing
		// Example: MOV $0xfffffffffffffff8, rcx; MOV rax, FS:(rcx)
		// or: MOV 0x40b9af9(RIP), rcx; MOV rax, FS:(rcx)
		// The interpreter handles RIP-relative addressing transparently,
		// resolving it to a virtual memory address.
		actual := it.Regs.GetX86(mem.Base)
		if actual.Match(offset) {
			return int32(offset.CapturedValue()), nil
		}
		// Pattern 3 continued: If the register value is a memory reference,
		// read from the file to resolve it
		if file != nil {
			addr := e.NewImmediateCapture("addr")
			if actual.Match(e.Mem8(addr)) {
				valueBytes, err := file.VirtualMemory(int64(addr.CapturedValue()), 8, 8)
				if err != nil {
					continue
				}
				// Read the 8-byte value as int64 (little-endian)
				value := int64(npsr.Uint64(valueBytes, 0))
				return int32(value), nil
			}
		}
	}
	return 0, fmt.Errorf("could not find FS-relative MOV instruction with valid TLS offset")
}
