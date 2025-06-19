//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"golang.org/x/arch/arm64/arm64asm"
)

// https://github.com/golang/go/blob/6885bad7dd86880be/src/runtime/tls_arm64.s#L11
//
//	Get's compiled into:
//	0x000000000007f260 <+0>:     adrp    x27, 0x1c2000 <runtime.mheap_+101440>
//	0x000000000007f264 <+4>:     ldrsb   x0, [x27, #284]
//	0x000000000007f268 <+8>:     cbz     x0, 0x7f278 <runtime.load_g+24>
//	0x000000000007f26c <+12>:    mrs     x0, tpidr_el0
//	0x000000000007f270 <+16>:    mov     x27, #0x30                      // #48
//	0x000000000007f274 <+20>:    ldr     x28, [x0, x27]
//	0x000000000007f278 <+24>:    ret
func extractTLSGOffset(f *pfelf.File) (int32, error) {
	iscgo, err := f.IsCgoEnabled()
	if err != nil || !iscgo {
		return 0, err
	}

	syms, err := f.ReadSymbols()
	if err != nil {
		return 0, err
	}
	sym, err := syms.LookupSymbol("runtime.load_g.abi0")
	if err != nil {
		// Binary must be stripped, just warn and return 0 and we'll rely on r28.
		log.Warnf("Failed to find load_g symbol in cgo enabled Go binary "+
			"label collection in CGO frames may not work: %v", err)
		return 0, nil
	}
	b, err := f.VirtualMemory(int64(sym.Address), 32, 32)
	if err != nil {
		return 0, err
	}
	for ; len(b) > 0; b = b[4:] {
		i, err := arm64asm.Decode(b)
		if err != nil {
			return 0, err
		}
		if i.Op == arm64asm.MOV {
			imm, ok := i.Args[1].(arm64asm.Imm64)
			if ok {
				return int32(imm.Imm), nil
			}
		}
	}
	log.Warnf("Failed to decode load_g symbol, Go label collection might not work with CGO frames")
	return 0, nil
}
