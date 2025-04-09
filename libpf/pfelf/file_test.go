// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"go/version"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/testsupport"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	xh "go.opentelemetry.io/ebpf-profiler/x86helpers"
	xx "golang.org/x/arch/x86/x86asm"
)

func getPFELF(path string, t *testing.T) *File {
	file, err := Open(path)
	assert.NoError(t, err)
	return file
}

func TestGnuHash(t *testing.T) {
	assert.Equal(t, uint32(0x00001505), calcGNUHash(""))
	assert.Equal(t, uint32(0x156b2bb8), calcGNUHash("printf"))
	assert.Equal(t, uint32(0x7c967e3f), calcGNUHash("exit"))
	assert.Equal(t, uint32(0xbac212a0), calcGNUHash("syscall"))
}

func lookupSymbolAddress(ef *File, name libpf.SymbolName) libpf.SymbolValue {
	val, _ := ef.LookupSymbolAddress(name)
	return val
}

func TestPFELFSymbols(t *testing.T) {
	exePath, err := testsupport.WriteSharedLibrary()
	require.NoError(t, err)
	defer os.Remove(exePath)

	ef, err := Open(exePath)
	require.NoError(t, err)
	defer ef.Close()

	// Test GNU hash lookup
	assert.Equal(t, libpf.SymbolValue(0x1000), lookupSymbolAddress(ef, "func"))
	assert.Equal(t, libpf.SymbolValueInvalid, lookupSymbolAddress(ef, "not_existent"))

	// Test SYSV lookup
	ef.gnuHash.addr = 0
	assert.Equal(t, libpf.SymbolValue(0x1000), lookupSymbolAddress(ef, "func"))
	assert.Equal(t, libpf.SymbolValueInvalid, lookupSymbolAddress(ef, "not_existent"))
}

func TestPFELFSections(t *testing.T) {
	elfFile, err := Open("testdata/fixed-address")
	require.NoError(t, err)
	defer elfFile.Close()

	// The fixed-address test executable has a section named `.coffee_section` at address 0xC0FFEE0
	sh := elfFile.Section(".coffee_section")
	if assert.NotNil(t, sh) {
		assert.Equal(t, ".coffee_section", sh.Name)
		assert.Equal(t, uint64(0xC0FFEE0), sh.Addr)

		// Try to find a section that does not exist
		sh = elfFile.Section(".tea_section")
		assert.Nil(t, sh)
	}
}

func testPFELFIsGolang(t *testing.T, filename string, isGoExpected bool) {
	ef := getPFELF(filename, t)
	defer ef.Close()
	assert.Equal(t, isGoExpected, ef.IsGolang())
}

func TestPFELFIsGolang(t *testing.T) {
	testPFELFIsGolang(t, "testdata/go-binary", true)
	testPFELFIsGolang(t, "testdata/without-debug-syms", false)
}

func TestGoVersion(t *testing.T) {
	ef := getPFELF("testdata/go-binary", t)
	defer ef.Close()

	vers, err := ef.GoVersion()
	require.NoError(t, err)
	assert.GreaterOrEqual(t, version.Compare(vers, "go1.23.6"), 0)

	testEF := getPFELF("/proc/self/exe", t)
	defer testEF.Close()
	testVersion, err := testEF.GoVersion()
	require.NoError(t, err)
	assert.Equal(t, runtime.Version(), testVersion)
}

func symbolOffsetFromCodeX86(code []byte) (int64, error) {
	// e.g. mov    eax,DWORD PTR fs:0xfffffffffffffffc
	code, _ = xh.SkipEndBranch(code)
	offset := 0
	for {
		insn, err := xx.Decode(code[offset:], 64)
		if err != nil {
			return 0, err
		}
		offset += insn.Len
		if insn.Op != xx.MOV {
			continue
		}
		switch a := insn.Args[1].(type) {
		case xx.Mem:
			if a.Segment != xx.FS {
				continue
			}
			// for some reason the Go disassembler
			// reports the displacement as a 32-bit value
			// embedded in a 64-bit one; e.g., it represents -16 as 0x00000000fffffff0 .
			// So this double cast is necessary.
			return int64(int32(a.Disp)), nil
		default:
			continue
		}
	}
}

func TestLookupTlsSymbolOffset(t *testing.T) {
	for _, test := range []struct {
		exe      string
		hasTbss  bool
		hasTdata bool
	}{
		{"tls-tbss", true, false},
		{"tls-aligned-tbss", true, false},
		{"tls-tdata", false, true},
		{"tls-aligned-tdata", false, true},
		{"tls-tbss-tdata", true, true},
		{"tls-aligned-tbss-tdata", true, true},
		{"tls-tbss-aligned-tdata", true, true},
		{"tls-aligned-tbss-aligned-tdata", true, true},
	} {
		// Testing this on arm is nontrivial, because we need to actually follow some
		// pointers in-process to get the address of the tls block. So let's
		// ignore it and just test x86.
		if runtime.GOARCH != "amd64" {
			t.Skip("this test is only supported on x86")
		}
		ef, err := Open("testdata/" + test.exe)
		require.NoError(t, err)

		if test.hasTbss {
			sym, err := ef.LookupSymbol("get_tbss")
			require.NoError(t, err)
			code := make([]byte, sym.Size)
			_, err = ef.ReadVirtualMemory(code, int64(sym.Address))
			require.NoError(t, err)

			offset, err := symbolOffsetFromCodeX86(code)
			require.NoError(t, err)

			offset2, err := ef.LookupTLSSymbolOffset("tbss")
			require.NoError(t, err)

			require.Equal(t, offset, offset2)
		}
		if test.hasTdata {
			sym, err := ef.LookupSymbol("get_tdata")
			require.NoError(t, err)
			code := make([]byte, sym.Size)
			_, err = ef.ReadVirtualMemory(code, int64(sym.Address))
			require.NoError(t, err)

			offset, err := symbolOffsetFromCodeX86(code)
			require.NoError(t, err)

			offset2, err := ef.LookupTLSSymbolOffset("tdata")
			require.NoError(t, err)

			require.Equal(t, offset, offset2)
		}
	}
}
