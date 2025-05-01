// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"errors"
	"fmt"
	"go/version"
	"os"
	"reflect"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/testsupport"
	"golang.org/x/exp/mmap"

	"go.opentelemetry.io/ebpf-profiler/libpf"
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

func TestMmapSection(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), t.Name()+".testfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())

	t.Run("invalid reader", func(t *testing.T) {
		readerValue := reflect.ValueOf(f).Elem()
		_, err := mmapSection(readerValue, 0, 1)
		if !errors.Is(err, errInvalReader) {
			t.Fatalf("expected %v but got %v", errInvalReader, err)
		}
	})

	testData := "data-for-the-test"

	t.Run("valid reader", func(t *testing.T) {
		fmt.Fprintf(f, "%s", testData)
		mf, err := mmap.Open(f.Name())
		if err != nil {
			t.Fatal(err)
		}
		defer mf.Close()

		readerValue := reflect.ValueOf(mf).Elem()

		t.Run("invalid request", func(t *testing.T) {
			// Try to access data out of scope from the data
			// in the backing file.
			_, err := mmapSection(readerValue, 1024, 1024)
			if !errors.Is(err, errInvalRequest) {
				t.Fatalf("expected %v but got %v", errInvalRequest, err)
			}
		})

		t.Run("valid request", func(t *testing.T) {
			// Try to access data out within the scope of
			// len(testData).
			res, err := mmapSection(readerValue, 9, 8)
			if err != nil {
				t.Fatalf("expected no error but got %v", err)
			}
			if string(res) != testData[9:] {
				t.Fatalf("expected '%s' but got '%s'", testData[9:], string(res))
			}
		})
	})
}
