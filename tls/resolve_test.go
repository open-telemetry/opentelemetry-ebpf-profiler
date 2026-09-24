// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"debug/elf"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

// Both are rejected before the file is looked at, hence the zero File.
func TestResolveRejectsNonThreadLocal(t *testing.T) {
	tests := map[string]libpf.Symbol{
		"undefined entry": {Name: "tls_var", Info: uint8(elf.STT_TLS)},
		"undefined entry with nonzero value and size": {Name: "tls_var", Address: 0x20,
			Size: 8, Info: uint8(elf.STT_TLS)},
		"another type by the same name": {Name: "tls_var", Address: 0x20, Size: 8,
			Info: uint8(elf.STT_OBJECT), Shndx: 1},
	}

	for name, sym := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Resolve(&pfelf.File{}, &sym)
			require.ErrorIs(t, err, ErrNotThreadLocal)
		})
	}
}

func TestResolveDefinedZeroValueAndSize(t *testing.T) {
	sym := libpf.Symbol{Name: "tls_var", Info: uint8(elf.STT_TLS), Shndx: 1}
	ef := &pfelf.File{Machine: elf.EM_X86_64}

	// A defined symbol at offset zero with size zero passes validation; this
	// empty file simply has no supported access model for it.
	_, err := Resolve(ef, &sym)
	require.ErrorIs(t, err, ErrUnsupportedModel)
}
