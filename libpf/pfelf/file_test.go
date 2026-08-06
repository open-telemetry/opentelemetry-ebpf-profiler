// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"bytes"
	"debug/buildinfo"
	"go/version"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/testsupport"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func getPFELF(path string, t *testing.T) *File {
	t.Helper()
	testsupport.RequireGeneratedTestFile(t, path)
	file, err := Open(path)
	require.NoError(t, err)
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
	testsupport.RequireGeneratedTestFile(t, "testdata/fixed-address")
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

	vers := ef.GoVersion()
	assert.GreaterOrEqual(t, version.Compare(vers, "go1.23.6"), 0)

	testEF := getPFELF("/proc/self/exe", t)
	defer testEF.Close()
	testVersion := testEF.GoVersion()
	assert.Equal(t, runtime.Version(), testVersion)
}

func TestParseGoBuildinfoFallback(t *testing.T) {
	want, err := buildinfo.ReadFile("testdata/go-binary")
	require.NoError(t, err)

	// magicStripped loads go-binary-no-sections and zeroes out the
	// buildinfo magic in memory, simulating a coredump so incomplete that
	// even the PT_LOAD fallback scan can't locate it.
	magicStripped := func(t *testing.T) *File {
		testsupport.RequireGeneratedTestFile(t, "testdata/go-binary-no-sections")
		raw, err := os.ReadFile("testdata/go-binary-no-sections")
		require.NoError(t, err)

		i := bytes.Index(raw, goBuildInfoMagic)
		require.GreaterOrEqualf(t, i, 0, "test fixture no longer contains the buildinfo magic %q", goBuildInfoMagic)
		corrupted := append([]byte(nil), raw...)
		clear(corrupted[i : i+len(goBuildInfoMagic)])

		ef, err := NewFile(bytes.NewReader(corrupted), 0, false)
		require.NoError(t, err)
		return ef
	}
	open := func(path string) func(t *testing.T) *File {
		return func(t *testing.T) *File { return getPFELF(path, t) }
	}

	tests := map[string]struct {
		open              func(t *testing.T) *File
		wantSection       bool
		wantOtherSections bool
		wantIsGolang      bool
		wantVersion       string
	}{
		"buildinfo section present": {
			open:        open("testdata/go-binary"),
			wantSection: true, wantOtherSections: true,
			wantIsGolang: true, wantVersion: want.GoVersion,
		},
		"buildinfo section renamed away": {
			open:        open("testdata/go-binary-no-buildinfo-section"),
			wantSection: false, wantOtherSections: true,
			wantIsGolang: true, wantVersion: want.GoVersion,
		},
		"no section headers at all": {
			open:        open("testdata/go-binary-no-sections"),
			wantSection: false, wantOtherSections: false,
			wantIsGolang: true, wantVersion: want.GoVersion,
		},
		"not a Go binary": {
			open:        open("testdata/without-debug-syms"),
			wantSection: false, wantOtherSections: false,
			wantIsGolang: false, wantVersion: "",
		},
		"buildinfo magic missing from a section-less ELF": {
			open:        magicStripped,
			wantSection: false, wantOtherSections: false,
			wantIsGolang: true, wantVersion: "",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			ef := tc.open(t)
			defer ef.Close()

			assert.Equal(t, tc.wantSection, ef.Section(".go.buildinfo") != nil)
			assert.Equal(t, tc.wantOtherSections, ef.Section(".gopclntab") != nil)
			assert.Equal(t, tc.wantIsGolang, ef.IsGolang())
			assert.Equal(t, tc.wantVersion, ef.GoVersion())
		})
	}
}

func TestGetGoBuildID(t *testing.T) {
	ef := getPFELF("testdata/go-binary", t)
	defer ef.Close()

	buildID, err := ef.GetGoBuildID()
	require.NoError(t, err)
	testsupport.RequireGeneratedTestFile(t, "testdata/go-binary")
	out, err := exec.Command("go", "tool", "buildid", "testdata/go-binary").Output()
	require.NoError(t, err)
	expectedBuildID := strings.TrimRight(string(out), "\n")
	assert.Equal(t, expectedBuildID, buildID)
}
