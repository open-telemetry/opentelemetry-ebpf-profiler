// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package native

import (
	"debug/elf"
	"io"
	"os"
	"runtime"
	"slices"
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
	"go.opentelemetry.io/ebpf-profiler/testsupport"
)

func requireNativeTestBin(t *testing.T, path string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("native ELF test binary is only built on Linux")
	}
	testsupport.RequireGeneratedTestFile(t, path)
}

func TestDedupeAliases(t *testing.T) {
	var strtab []byte
	sym := func(name string, address, size uint32, local bool) rankedSymbol {
		strtab = append(strtab, 0)
		nameOff := uint32(len(strtab))
		strtab = append(strtab, name...)
		return rankedSymbol{symbolEntry{address, size, nameOff}, local}
	}
	syms := []rankedSymbol{
		sym("__GI___clone", 0x1000, 0x10, true),
		sym("__clone", 0x1000, 0x10, false),
		sym("clone", 0x1000, 0x10, false),
		sym("___pthread_cond_wait", 0x2000, 0x10, true),
		sym("pthread_cond_wait@GLIBC_2.17", 0x2000, 0x10, false),
		sym("pthread_cond_wait@@GLIBC_2.34", 0x2000, 0x10, false),
		sym("__libc_start_main_impl", 0x3000, 0x10, true),
		sym("__libc_start_main@@GLIBC_2.34", 0x3000, 0x10, false),
		sym("Py_RunMain.localalias", 0x4000, 0x10, true),
		sym("Py_RunMain", 0x4000, 0x10, false),
		sym("a_local", 0x5000, 0x10, true),
		sym("the_exported", 0x5000, 0x10, false),
		sym("inner", 0x6000, 0x10, false),
		sym("outer", 0x6000, 0x20, false),
	}
	strtab = append(strtab, 0)

	want := []string{"clone", "pthread_cond_wait", "__libc_start_main", "Py_RunMain",
		"the_exported", "outer", "inner"}
	for _, reversed := range []bool{false, true} {
		in := slices.Clone(syms)
		if reversed {
			slices.Reverse(in)
		}
		var got []string
		for _, s := range dedupeAliases(strtab, in) {
			got = append(got, string(rawName(strtab, s.nameOff)))
		}
		assert.Equal(t, want, got, "reversed input: %v", reversed)
	}
}

func TestDebugSymbolsOptIn(t *testing.T) {
	requireNativeTestBin(t, "testdata/testbin-symtab")

	tests := []struct {
		name       string
		cfg        Config
		wantSymtab bool
	}{
		{"dynsym only by default", Config{}, false},
		{"symtab with debug symbols", Config{DebugSymbols: true}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			elfRef := pfelf.NewReference("testbin-symtab", os.DirFS("testdata"))
			data, err := load(tt.cfg, interpreter.NewLoaderInfo(host.FileID(1), elfRef, nil))
			require.NoError(t, err)
			require.NotNil(t, data)
			defer data.Unload(nil)
			assert.Equal(t, tt.wantSymtab, data.(*nativeData).strtab != nil)
		})
	}
}

func TestLoaderSkipsGoBinary(t *testing.T) {
	exec, err := os.Executable()
	require.NoError(t, err)

	elfRef := pfelf.NewReference(exec, os.DirFS("/"))

	hostFileID, err := host.FileIDFromBytes(
		[]byte{0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55, 0xAA, 0x55})
	require.NoError(t, err)

	loaderInfo := interpreter.NewLoaderInfo(hostFileID, elfRef, nil)
	data, err := load(Config{}, loaderInfo)
	if err != nil && strings.Contains(err.Error(), "not an ELF file") {
		t.Skip("test executable is not an ELF binary")
	}
	require.NoError(t, err)
	assert.Nil(t, data, "Loader should skip Go binaries")
}

func TestLookupSymbol(t *testing.T) {
	strtab := []byte("\x00func_a\x00func_b@@V_1\x00func_c@V_2\x00") // offsets 1, 8, 20

	syncedCache, err := lru.NewSynced[uint32, libpf.String](64, hash.Uint32)
	require.NoError(t, err)

	d := &nativeData{
		symbols: map[uint32][]symbolEntry{
			0: {
				{address: 0x1000, size: 0x100, nameOff: 1},
				{address: 0x1100, size: 0x100, nameOff: 8},
				{address: 0x2000, size: 0x50, nameOff: 20},
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
			assert.Equal(t, tt.wantName, inst.symbolName(nameOff).String(), "addr 0x%x", tt.addr)
		}
	}
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
	requireNativeTestBin(t, "testdata/testbin-dynsym")

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
	data, err := load(Config{}, interpreter.NewLoaderInfo(hostFileID, elfRef, nil))
	require.NoError(t, err)
	require.NotNil(t, data)
	symData := data.(*nativeData)
	assert.Nil(t, symData.strtab, ".dynsym names must not be kept from the file")
	assert.NotZero(t, symData.dynstrAddr)

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

	fallbacks := []struct {
		name   string
		fileID host.FileID
		addr   uint64
	}{
		{"other file", hostFileID + 1, symData.dynstrAddr},
		{"no symbol", hostFileID, 1},
	}
	for _, tt := range fallbacks {
		t.Run(tt.name, func(t *testing.T) {
			ef := libpf.NewEbpfFrame(libpf.NativeFrame, 0, 2, tt.addr)
			ef[1] = uint64(tt.fileID)
			var frames libpf.Frames
			err := instance.Symbolize(ef, &frames, libpf.FrameMapping{})
			require.ErrorIs(t, err, interpreter.ErrMismatchInterpreterType)
			assert.Empty(t, frames)
		})
	}
}
