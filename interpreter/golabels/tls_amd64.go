//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"golang.org/x/arch/x86/x86asm"
)

// Most normal amd64 Go binaries use -8 as offset into TLS space for
// storing the current g but "static" binaries it ends up as -80. There
// may be dynamic relocating going on so just read it from a known
// symbol if possible.
func extractTLSGOffset(f *pfelf.File) (int32, error) {
	syms, err := f.ReadSymbols()
	if err != nil {
		return 0, err
	}
	// Dump of assembler code for function runtime.stackcheck:
	// 0x0000000000470080 <+0>:     mov    %fs:0xfffffffffffffff8,%rax
	sym, err := syms.LookupSymbol("runtime.stackcheck.abi0")
	if err != nil {
		// Binary must be stripped, hope default is correct and warn.
		log.Warnf("Failed to find stackcheck symbol, Go labels might not work: %v", err)
		return -8, nil
	}
	b, err := f.VirtualMemory(int64(sym.Address), 10, 10)
	if err != nil {
		return 0, err
	}

	i, err := x86asm.Decode(b, 64)
	if err != nil {
		return 0, err
	}
	if i.Op == x86asm.MOV {
		mem, ok := i.Args[1].(x86asm.Mem)
		if ok {
			return int32(mem.Disp), nil
		}
	}
	log.Warnf("Failed to decode stackcheck symbol, Go label collection might not work")
	return -8, nil
}
