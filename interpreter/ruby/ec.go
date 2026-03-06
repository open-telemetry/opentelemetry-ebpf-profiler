// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/asm/amd"
	"go.opentelemetry.io/ebpf-profiler/asm/arm"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// extractEcTLSOffset extracts the direct TP-relative TLS offset for ruby_current_ec
// by disassembling rb_current_ec_noinline. This is used for statically-linked Ruby
// binaries where TLS descriptors are not available.
//
// The function uses the same TLS extraction infrastructure as Python 3.13+
// (asm/amd.ExtractTLSOffset and asm/arm.ExtractTLSOffset).
func extractEcTLSOffset(ef *pfelf.File) (int64, error) {
	symbolName := libpf.SymbolName("rb_current_ec_noinline")
	sym, code, err := ef.SymbolData(symbolName, 2048)
	if err != nil {
		// Fallback: try VisitSymbols for binaries with local symbols not in .dynsym
		sym = &libpf.Symbol{}
		found := false
		if visitErr := ef.VisitSymbols(func(s libpf.Symbol) bool {
			if s.Name == symbolName {
				data, readErr := ef.VirtualMemory(int64(s.Address), int(s.Size), 2048)
				if readErr != nil {
					log.Errorf("Failed to read memory for %s: %v", symbolName, readErr)
				} else {
					code = data
					sym.Address = s.Address
					found = true
				}
				return false
			}
			return true
		}); visitErr != nil {
			return 0, fmt.Errorf("failed to visit symbols: %w", visitErr)
		}
		if !found {
			return 0, fmt.Errorf("symbol %s not found", symbolName)
		}
	}

	if len(code) < 4 {
		return 0, fmt.Errorf("%s function too small (%d bytes)", symbolName, len(code))
	}

	var offset int32
	switch ef.Machine {
	case elf.EM_X86_64:
		offset, err = amd.ExtractTLSOffset(code, uint64(sym.Address), nil)
	case elf.EM_AARCH64:
		offset, err = arm.ExtractTLSOffset(code, uint64(sym.Address), ef)
	default:
		return 0, fmt.Errorf("unsupported architecture: %s", ef.Machine)
	}
	if err != nil {
		return 0, fmt.Errorf("failed to extract TLS offset from %s: %w", symbolName, err)
	}

	return int64(offset), nil
}
