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
		"another type by the same name": {Name: "tls_var", Address: 0x20, Size: 8,
			Info: uint8(elf.STT_OBJECT)},
	}

	for name, sym := range tests {
		t.Run(name, func(t *testing.T) {
			_, err := Resolve(&pfelf.File{}, &sym)
			require.ErrorIs(t, err, ErrNotThreadLocal)
		})
	}
}
