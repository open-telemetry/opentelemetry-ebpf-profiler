/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package pfelf

import (
	"os"
	"testing"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/testsupport"
	"github.com/stretchr/testify/assert"
)

func getPFELF(path string, t *testing.T) *File {
	file, err := Open(path)
	assert.Nil(t, err)
	return file
}

func TestGnuHash(t *testing.T) {
	assert.Equal(t, calcGNUHash(""), uint32(0x00001505))
	assert.Equal(t, calcGNUHash("printf"), uint32(0x156b2bb8))
	assert.Equal(t, calcGNUHash("exit"), uint32(0x7c967e3f))
	assert.Equal(t, calcGNUHash("syscall"), uint32(0xbac212a0))
}

func lookupSymbolAddress(ef *File, name libpf.SymbolName) libpf.SymbolValue {
	val, _ := ef.LookupSymbolAddress(name)
	return val
}

func TestPFELFSymbols(t *testing.T) {
	exePath, err := testsupport.WriteSharedLibrary()
	if err != nil {
		t.Fatalf("Failed to write test executable: %v", err)
	}
	defer os.Remove(exePath)

	ef, err := Open(exePath)
	if err != nil {
		t.Fatalf("Failed to open test executable: %v", err)
	}
	defer ef.Close()

	// Test GNU hash lookup
	assert.Equal(t, lookupSymbolAddress(ef, "func"), libpf.SymbolValue(0x1000))
	assert.Equal(t, lookupSymbolAddress(ef, "not_existent"), libpf.SymbolValueInvalid)

	// Test SYSV lookup
	ef.gnuHash.addr = 0
	assert.Equal(t, lookupSymbolAddress(ef, "func"), libpf.SymbolValue(0x1000))
	assert.Equal(t, lookupSymbolAddress(ef, "not_existent"), libpf.SymbolValueInvalid)
}

func TestPFELFSections(t *testing.T) {
	elfFile, err := Open("testdata/fixed-address")
	if !assert.Nil(t, err) {
		return
	}
	defer elfFile.Close()

	// The fixed-address test executable has a section named `.coffee_section` at address 0xC0FFEE
	sh := elfFile.Section(".coffee_section")
	if assert.NotNil(t, sh) {
		assert.Equal(t, sh.Name, ".coffee_section")
		assert.Equal(t, sh.Addr, uint64(0xC0FFEE))

		// Try to find a section that does not exist
		sh = elfFile.Section(".tea_section")
		assert.Nil(t, sh)
	}
}

func testPFELFIsGolang(t *testing.T, filename string, isGoExpected bool) {
	ef := getPFELF(filename, t)
	defer ef.Close()
	assert.Equal(t, ef.IsGolang(), isGoExpected)
}

func TestPFELFIsGolang(t *testing.T) {
	testPFELFIsGolang(t, "testdata/go-binary", true)
	testPFELFIsGolang(t, "testdata/without-debug-syms", false)
}
