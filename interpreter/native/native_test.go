// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package native

import (
	"os"
	"testing"

	lru "github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestLoaderSkipsGoBinary(t *testing.T) {
	exec, err := os.Executable()
	require.NoError(t, err)

	elfRef := pfelf.NewReference(exec, pfelf.SystemOpener)

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef)
	data, err := Loader(nil, loaderInfo)
	require.NoError(t, err)
	assert.Nil(t, data, "Loader should skip Go binaries")
}

func TestLoaderNativeBinary(t *testing.T) {
	// Use testdata/testbin as a native (non-Go) ELF with .dynsym symbols.
	elfRef := pfelf.NewReference("testdata/testbin", pfelf.SystemOpener)

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef)
	data, err := Loader(nil, loaderInfo)
	require.NoError(t, err)
	require.NotNil(t, data, "expected native symbolizer data for testdata/testbin")

	nd, ok := data.(*nativeData)
	require.True(t, ok)
	assert.Greater(t, len(nd.symbols), 0)
}

func TestSymbolize(t *testing.T) {
	elfRef := pfelf.NewReference("testdata/testbin", pfelf.SystemOpener)

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef)
	data, err := Loader(nil, loaderInfo)
	require.NoError(t, err)
	require.NotNil(t, data)

	nd := data.(*nativeData)
	require.Greater(t, len(nd.symbols), 0)

	sym := nd.symbols[len(nd.symbols)/2]

	instance, err := data.Attach(nil, 0, 0, remotememory.RemoteMemory{})
	require.NoError(t, err)

	ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, sym.address)
	ef[1] = uint64(hostFileID)

	var frames libpf.Frames
	err = instance.Symbolize(ef, &frames, libpf.FrameMapping{})
	require.NoError(t, err)
	require.Len(t, frames, 1)

	frame := frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, frame.Type)

	// Resolve the expected name the same way the symbolizer does.
	expectedName := nd.resolveSymbolName(sym.nameOff)
	assert.Equal(t, expectedName, frame.FunctionName.String())
}

func TestSymbolizeMismatch(t *testing.T) {
	elfRef := pfelf.NewReference("testdata/testbin", pfelf.SystemOpener)

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef)
	data, err := Loader(nil, loaderInfo)
	require.NoError(t, err)
	require.NotNil(t, data)

	instance, err := data.Attach(nil, 0, 0, remotememory.RemoteMemory{})
	require.NoError(t, err)

	wrongFileID, err := host.FileIDFromBytes(
		[]byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	require.NoError(t, err)

	ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, 0x1000)
	ef[1] = uint64(wrongFileID)

	var frames libpf.Frames
	err = instance.Symbolize(ef, &frames, libpf.FrameMapping{})
	assert.ErrorIs(t, err, interpreter.ErrMismatchInterpreterType)
	assert.Empty(t, frames)
}

func TestLookupSymbol(t *testing.T) {
	// Build a synthetic string table: "func_a\0func_b\0func_c\0"
	strtab := []byte("\x00func_a\x00func_b\x00func_c\x00")
	// offsets: func_a=1, func_b=8, func_c=15

	cache, err := lru.New[uint32, string](64, hash.Uint32)
	require.NoError(t, err)

	d := &nativeData{
		symbols: []symbolEntry{
			{address: 0x1000, end: 0x1100, nameOff: 1},
			{address: 0x1100, end: 0x1200, nameOff: 8},
			{address: 0x2000, end: 0x2050, nameOff: 15},
		},
		strtab:    strtab,
		nameCache: cache,
	}

	tests := []struct {
		addr     uint64
		wantName string
		wantOK   bool
	}{
		{0x1000, "func_a", true},
		{0x10FF, "func_a", true},
		{0x1100, "func_b", true},
		{0x1200, "", false},
		{0x2000, "func_c", true},
		{0x2049, "func_c", true},
		{0x2050, "", false},
		{0x0FFF, "", false},
		{0x3000, "", false},
	}

	for _, tt := range tests {
		name, ok := d.lookupSymbol(tt.addr)
		assert.Equal(t, tt.wantOK, ok, "addr 0x%x", tt.addr)
		assert.Equal(t, tt.wantName, name, "addr 0x%x", tt.addr)
	}
}

func TestDemangleSymbol(t *testing.T) {
	tests := []struct {
		input     string
		demangled bool
	}{
		// C++ Itanium ABI — should be demangled
		{"_ZN3foo3barEv", true},
		{"_ZNSt6vectorIiSaIiEE9push_backEOi", true},
		// Rust legacy (_ZN) — handled by demangle
		{"_ZN4core3fmt5write17h01234567890abcdeE", true},
		// Not mangled — returned as-is
		{"main", false},
		{"printf", false},
		{"_start", false},
		// Invalid mangling — returned as-is
		{"_Z", false},
	}

	for _, tt := range tests {
		got := demangleSymbol(tt.input)
		if tt.demangled {
			assert.NotEqual(t, tt.input, got,
				"expected demangling for %q, got %q", tt.input, got)
		} else {
			assert.Equal(t, tt.input, got,
				"expected no demangling for %q", tt.input)
		}
	}
}
