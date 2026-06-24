//go:build arm64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package golabels // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels"

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/testsupport"
)

func TestExtractRuntimeIsCgo(t *testing.T) {
	tests := map[string]struct {
		fixture        string
		wantRuntimeCgo bool
	}{
		"nocgo binary": {
			fixture:        "testdata/golabels-nocgo.arm64",
			wantRuntimeCgo: false,
		},
		"buildinfo cgo without runtime cgo": {
			fixture:        "testdata/golabels-buildinfo-cgo.arm64",
			wantRuntimeCgo: false,
		},
		"runtime cgo": {
			fixture:        "testdata/golabels-cgo.arm64",
			wantRuntimeCgo: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			testsupport.RequireGeneratedTestFile(t, tt.fixture)

			f, err := pfelf.Open(tt.fixture)
			require.NoError(t, err)
			defer f.Close()

			pclntab, err := elfunwindinfo.NewGopclntab(f)
			require.NoError(t, err)
			defer pclntab.Close()

			sym, err := pclntab.LookupSymbol(libpf.SymbolName("runtime.load_g.abi0"))
			if err != nil {
				sym, err = pclntab.LookupSymbol(libpf.SymbolName("runtime.load_g"))
			}
			require.NoError(t, err)

			pc := int64(sym.Address)
			b, err := f.VirtualMemory(pc, runtimeIsCgoCodeSize, runtimeIsCgoCodeSize)
			require.NoError(t, err)

			runtimeCgo, err := extractRuntimeIsCgo(f, b, pc)
			require.NoError(t, err, "runtime.load_g prologue decode failed; Go runtime layout may have changed")
			require.Equal(t, tt.wantRuntimeCgo, runtimeCgo)
		})
	}
}
