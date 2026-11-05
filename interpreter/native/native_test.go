// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package native

import (
	"debug/elf"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
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

func requireNativeTestBin(t *testing.T, name string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("native ELF test binary is only built on Linux")
	}
	if _, err := os.Stat("testdata/" + name); err == nil {
		return
	}
	cmd := exec.Command("make", "-C", "testdata", name)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "failed to build native test binary: %s", out)
}

func TestLoaderSkipsGoBinary(t *testing.T) {
	exec, err := os.Executable()
	require.NoError(t, err)

	elfRef := pfelf.NewReference(exec, os.DirFS("/"))

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef, nil)
	data, err := load(Config{Enabled: true}, loaderInfo)
	if err != nil && strings.Contains(err.Error(), "not an ELF file") {
		t.Skip("test executable is not an ELF binary")
	}
	require.NoError(t, err)
	assert.Nil(t, data, "Loader should skip Go binaries")
}

func TestLoaderNativeBinary(t *testing.T) {
	requireNativeTestBin(t, "testbin")

	elfRef := pfelf.NewReference("testbin", os.DirFS("testdata"))

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef, nil)
	data, err := load(Config{Enabled: true}, loaderInfo)
	require.NoError(t, err)
	require.NotNil(t, data, "expected native symbolizer data for testdata/testbin")

	nd, ok := data.(*nativeData)
	require.True(t, ok)
	assert.Greater(t, nd.numSyms, 0)
}

func TestSymbolize(t *testing.T) {
	requireNativeTestBin(t, "testbin")

	elfRef := pfelf.NewReference("testbin", os.DirFS("testdata"))

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef, nil)
	data, err := load(Config{Enabled: true}, loaderInfo)
	require.NoError(t, err)
	require.NotNil(t, data)

	nd := data.(*nativeData)
	require.Greater(t, nd.numSyms, 0)

	sym := firstSymbol(nd)
	symAddr := (uint64(sym.high) << 32) | uint64(sym.entry.address)

	instance, err := data.Attach(nil, 0, 0, remotememory.RemoteMemory{})
	require.NoError(t, err)

	ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, symAddr)
	ef[1] = uint64(hostFileID)

	var frames libpf.Frames
	err = instance.Symbolize(ef, &frames, libpf.FrameMapping{})
	require.NoError(t, err)
	require.Len(t, frames, 1)

	frame := frames[0].Value()
	assert.Equal(t, libpf.NativeFrame, frame.Type)

	expectedName := instance.(*nativeInstance).symbolName(sym.entry.nameOff)
	assert.NotEmpty(t, expectedName)
	assert.Equal(t, expectedName, frame.FunctionName.String())
}

func TestSymbolizeMismatch(t *testing.T) {
	requireNativeTestBin(t, "testbin")

	elfRef := pfelf.NewReference("testbin", os.DirFS("testdata"))

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef, nil)
	data, err := load(Config{Enabled: true}, loaderInfo)
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
	strtab := []byte("\x00func_a\x00func_b\x00func_c\x00") // offsets 1, 8, 15

	syncedCache, err := lru.NewSynced[uint32, string](64, hash.Uint32)
	require.NoError(t, err)

	d := &nativeData{
		symbols: map[uint32][]symbolEntry{
			0: {
				{address: 0x1000, size: 0x100, nameOff: 1},
				{address: 0x1100, size: 0x100, nameOff: 8},
				{address: 0x2000, size: 0x50, nameOff: 15},
				{address: 0x3000, size: 0x200, nameOff: 1},
				{address: 0x3010, size: 0x10, nameOff: 8},
			},
		},
		strtab:    strtab,
		nameCache: syncedCache,
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
		{0x3000, "func_a", true},
		{0x3015, "func_b", true},
		{0x3050, "func_a", true}, // after the nested one
		{0x3200, "", false},
	}

	inst := &nativeInstance{d: d}
	for _, tt := range tests {
		nameOff, ok := d.lookupSymbol(tt.addr)
		assert.Equal(t, tt.wantOK, ok, "addr 0x%x", tt.addr)
		if ok {
			assert.Equal(t, tt.wantName, inst.symbolName(nameOff), "addr 0x%x", tt.addr)
		}
	}
}

type selectedSymbol struct {
	high  uint32
	entry symbolEntry
}

func firstSymbol(d *nativeData) selectedSymbol {
	for high, symbols := range d.symbols {
		if len(symbols) > 0 {
			return selectedSymbol{high: high, entry: symbols[len(symbols)/2]}
		}
	}
	return selectedSymbol{}
}

func TestDemangleSymbol(t *testing.T) {
	tests := []struct {
		input     string
		demangled bool
	}{
		{"_ZN3foo3barEv", true},
		{"_ZNSt6vectorIiSaIiEE9push_backEOi", true},
		{"_ZN4core3fmt5write17h01234567890abcdeE", true},
		{"main", false},
		{"printf", false},
		{"_start", false},
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

// fileMemory reads an ELF file as a process mapping it at bias 0 would.
type fileMemory struct {
	f *elf.File
	r io.ReaderAt
}

func (m fileMemory) ReadAt(p []byte, addr int64) (int, error) {
	for _, prog := range m.f.Progs {
		va := uint64(addr)
		if prog.Type == elf.PT_LOAD && va >= prog.Vaddr && va < prog.Vaddr+prog.Filesz {
			n := min(uint64(len(p)), prog.Vaddr+prog.Filesz-va)
			return m.r.ReadAt(p[:n], int64(prog.Off+va-prog.Vaddr))
		}
	}
	return 0, io.EOF
}

func TestSymbolizeDynsym(t *testing.T) {
	requireNativeTestBin(t, "testbin-dynsym")

	f, err := os.Open("testdata/testbin-dynsym")
	require.NoError(t, err)
	defer f.Close()
	stdELF, err := elf.NewFile(f)
	require.NoError(t, err)
	_, err = stdELF.Symbols()
	require.ErrorIs(t, err, elf.ErrNoSymbols, "fixture must be stripped of .symtab")
	dynsyms, err := stdELF.DynamicSymbols()
	require.NoError(t, err)

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)
	elfRef := pfelf.NewReference("testbin-dynsym", os.DirFS("testdata"))
	data, err := load(Config{Enabled: true}, interpreter.NewLoaderInfo(hostFileID, elfRef, nil))
	require.NoError(t, err)
	require.NotNil(t, data)
	nd := data.(*nativeData)
	assert.Nil(t, nd.strtab, ".dynsym names must not be kept from the file")
	assert.NotZero(t, nd.dynstrAddr)

	rm := remotememory.RemoteMemory{ReaderAt: fileMemory{f: stdELF, r: f}}
	instance, err := data.Attach(nil, 0, 0, rm)
	require.NoError(t, err)

	for _, want := range []string{"func_alpha", "func_beta", "func_gamma"} {
		t.Run(want, func(t *testing.T) {
			var addr uint64
			for _, sym := range dynsyms {
				if sym.Name == want {
					addr = sym.Value
				}
			}
			require.NotZero(t, addr, "%s missing from .dynsym", want)

			ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, addr)
			ef[1] = uint64(hostFileID)
			var frames libpf.Frames
			require.NoError(t, instance.Symbolize(ef, &frames, libpf.FrameMapping{}))
			require.Len(t, frames, 1)
			assert.Equal(t, want, frames[0].Value().FunctionName.String())
		})
	}
}

func TestLoaderConfig(t *testing.T) {
	requireNativeTestBin(t, "testbin")

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)
	loadWith := func(cfg Config) interpreter.Data {
		elfRef := pfelf.NewReference("testbin", os.DirFS("testdata"))
		data, err := load(cfg, interpreter.NewLoaderInfo(hostFileID, elfRef, nil))
		require.NoError(t, err)
		return data
	}
	numSyms := loadWith(Config{Enabled: true}).(*nativeData).numSyms
	require.Greater(t, numSyms, 1)

	tests := []struct {
		name     string
		cfg      Config
		loaded   bool
		cacheCap int
	}{
		{"defaults", Config{Enabled: true}, true, defaultNameCacheSize},
		{"cache size", Config{Enabled: true, NameCacheSize: 2}, true, 2},
		{"at max symbols", Config{Enabled: true, MaxSymbols: uint32(numSyms)}, true, defaultNameCacheSize},
		{"over max symbols", Config{Enabled: true, MaxSymbols: uint32(numSyms - 1)}, false, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := loadWith(tt.cfg)
			if !tt.loaded {
				assert.Nil(t, data)
				return
			}
			require.NotNil(t, data)
			nd := data.(*nativeData)
			for off := range uint32(tt.cacheCap + 1) {
				nd.nameCache.Add(off, "")
			}
			assert.Equal(t, tt.cacheCap, nd.nameCache.Len())
		})
	}
}
