//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	"errors"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"golang.org/x/arch/x86/x86asm"
)

var (
	errMissingSymbol = errors.New("failed to find runtime.stackcheck")
	errUnexpectedAsm = errors.New("failed to disassemble runtime.stackcheck")
)

// virtualMemoryReader allows to mock pfelf.File for testing.
type virtualMemoryReader interface {
	VirtualMemory(addr int64, size int, align int) ([]byte, error)
}

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

	// Dump of assembler code for function runtime.stackcheck:
	// Case 1 - direct offset
	//   mov %fs:0xfffffffffffffff8,%rax
	// Case 2 - indirect offset
	//   mov 0x17d0c5a1(%rip),%rcx
	//   mov %fs:(%rcx),%rax
	pc, ok := pclntab.PCForSymbol("runtime.stackcheck")
	if !ok {
		return 0, errMissingSymbol
	}
	// Read enough bytes for two instructions
	b, err := f.VirtualMemory(int64(pc), 16, 16)
	if err != nil {
		return 0, err
	}
	return extractOffsetFromBytes(f, pc, b)
}

func extractOffsetFromBytes(f virtualMemoryReader, pc uintptr, b []byte) (int32, error) {
	i1, err := x86asm.Decode(b, 64)
	if err != nil {
		return 0, err
	}

	// Case 1: mov %fs:0xfffffffffffffff8,%rax
	if i1.Op == x86asm.MOV {
		mem, ok := i1.Args[1].(x86asm.Mem)
		reg, okReg := i1.Args[0].(x86asm.Reg)
		if ok && okReg && mem.Segment == x86asm.FS && reg == x86asm.RAX {
			return int32(mem.Disp), nil
		}
	}

	i2, err := x86asm.Decode(b[i1.Len:], 64)
	if err != nil {
		return 0, err
	}

	// Case 2: mov 0x17d0c5a1(%rip),%rcx; mov %fs:(%rcx),%rax
	if i1.Op == x86asm.MOV && i2.Op == x86asm.MOV {
		mem1, ok1 := i1.Args[1].(x86asm.Mem)
		reg1, okReg1 := i1.Args[0].(x86asm.Reg)
		mem2, ok2 := i2.Args[1].(x86asm.Mem)
		reg2, okReg2 := i2.Args[0].(x86asm.Reg)
		reg2base := mem2.Base
		// Check for the indirect pattern
		if ok1 && okReg1 && ok2 && okReg2 && reg1 == x86asm.RCX && mem2.Segment == x86asm.FS &&
			reg2 == x86asm.RAX && reg2base == x86asm.RCX {
			// Resolve the address loaded by the first instruction (RIP-relative)
			addr := int64(pc) + int64(i1.Len) + mem1.Disp
			offsetBytes, err := f.VirtualMemory(addr, 4, 4)
			if err != nil {
				return 0, errUnexpectedAsm
			}
			offset := int32(offsetBytes[0]) |
				int32(offsetBytes[1])<<8 |
				int32(offsetBytes[2])<<16 |
				int32(offsetBytes[3])<<24
			return offset, nil
		}
	}

	return 0, errUnexpectedAsm
}
