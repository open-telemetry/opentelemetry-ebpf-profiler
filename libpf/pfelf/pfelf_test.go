/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package pfelf_test

import (
	"debug/elf"
	"encoding/hex"
	"os"
	"testing"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/testsupport"
	"github.com/stretchr/testify/assert"
)

var (
	// An ELF without DWARF symbols
	withoutDebugSymsPath = "testdata/without-debug-syms"
	// An ELF with DWARF symbols
	withDebugSymsPath = "testdata/with-debug-syms"
	// An ELF with only DWARF symbols
	separateDebugFile = "testdata/separate-debug-file"
)

func getELF(path string, t *testing.T) *elf.File {
	file, err := elf.Open(path)
	assert.Nil(t, err)
	return file
}

func TestGetBuildID(t *testing.T) {
	debugExePath, err := testsupport.WriteTestExecutable1()
	if err != nil {
		t.Fatalf("Failed to write test executable: %v", err)
	}
	defer os.Remove(debugExePath)

	elfFile := getELF(debugExePath, t)
	defer elfFile.Close()

	buildID, err := pfelf.GetBuildID(elfFile)
	if err != nil {
		t.Fatalf("getBuildID failed with error: %s", err)
	}

	if buildID != "6920fd217a8416131f4377ef018a2c932f311b6d" {
		t.Fatalf("Invalid build-id: %s", buildID)
	}
}

func TestGetDebugLink(t *testing.T) {
	debugExePath, err := testsupport.WriteTestExecutable1()
	if err != nil {
		t.Fatalf("Failed to write test executable: %v", err)
	}
	defer os.Remove(debugExePath)

	elfFile := getELF(debugExePath, t)
	defer elfFile.Close()

	debugLink, crc32, err := pfelf.GetDebugLink(elfFile)
	if err != nil {
		t.Fatalf("getDebugLink failed with error: %s", err)
	}

	if debugLink != "dumpmscat-4.10.8-0.fc30.x86_64.debug" {
		t.Fatalf("Invalid debug link: %s", debugLink)
	}

	if uint32(crc32) != 0xfe3099b8 {
		t.Fatalf("Invalid debug link CRC32: %v", crc32)
	}
}

func TestGetBuildIDError(t *testing.T) {
	debugExePath, err := testsupport.WriteTestExecutable2()
	if err != nil {
		t.Fatalf("Failed to write test executable: %v", err)
	}
	defer os.Remove(debugExePath)

	elfFile := getELF(debugExePath, t)
	defer elfFile.Close()

	buildID, err := pfelf.GetBuildID(elfFile)
	if err != pfelf.ErrNoBuildID {
		t.Fatalf("Expected errNoBuildID but got: %s", err)
	}
	if buildID != "" {
		t.Fatalf("Expected an empty string but got: %s", err)
	}
}

func TestGetDebugLinkError(t *testing.T) {
	debugExePath, err := testsupport.WriteTestExecutable2()
	if err != nil {
		t.Fatalf("Failed to write test executable: %v", err)
	}
	defer os.Remove(debugExePath)

	elfFile := getELF(debugExePath, t)
	defer elfFile.Close()

	debugLink, _, err := pfelf.GetDebugLink(elfFile)
	if err != pfelf.ErrNoDebugLink {
		t.Fatalf("expected errNoDebugLink but got: %s", err)
	}

	if debugLink != "" {
		t.Fatalf("Expected an empty string but got: %s", err)
	}
}

func TestIsELF(t *testing.T) {
	if _, err := os.Stat(withoutDebugSymsPath); err != nil {
		t.Fatalf("Could not access test file %s: %v", withoutDebugSymsPath, err)
	}

	asciiFile, err := os.CreateTemp("", "pfelf_test_ascii_")
	if err != nil {
		t.Fatalf("Failed to open tempfile: %v", err)
	}

	_, err = asciiFile.WriteString("Some random ascii text")
	if err != nil {
		t.Fatalf("Failed to write to tempfile: %v", err)
	}
	asciiPath := asciiFile.Name()
	if err = asciiFile.Close(); err != nil {
		t.Fatalf("Error closing file: %v", err)
	}
	defer os.Remove(asciiPath)

	shortFile, err := os.CreateTemp("", "pfelf_test_short_")
	if err != nil {
		t.Fatalf("Failed to open tempfile: %v", err)
	}

	_, err = shortFile.Write([]byte{0x7f})
	if err != nil {
		t.Fatalf("Failed to write to tempfile: %v", err)
	}
	shortFilePath := shortFile.Name()
	if err := shortFile.Close(); err != nil {
		t.Fatalf("Error closing file: %v", err)
	}
	defer os.Remove(shortFilePath)

	tests := map[string]struct {
		filePath       string
		expectedResult bool
		expectedError  bool
	}{
		"ELF executable": {withoutDebugSymsPath, true, false},
		"ASCII file":     {asciiPath, false, false},
		"Short file":     {shortFilePath, false, false},
		"Invalid path":   {"/some/invalid/path", false, true},
	}

	for testName, testCase := range tests {
		name := testName
		tc := testCase
		t.Run(name, func(t *testing.T) {
			isELF, err := pfelf.IsELF(tc.filePath)
			if tc.expectedError {
				if err == nil {
					t.Fatalf("Expected an error but didn't get one")
				}
				return
			}

			if err != nil {
				t.Fatalf("%v", err)
			}

			if isELF != tc.expectedResult {
				t.Fatalf("Expected %v but got %v", tc.expectedResult, isELF)
			}
		})
	}
}

func TestHasDWARFData(t *testing.T) {
	tests := map[string]struct {
		filePath       string
		expectedResult bool
	}{
		"ELF executable - no DWARF":   {withoutDebugSymsPath, false},
		"ELF executable - with DWARF": {withDebugSymsPath, true},
		"Separate debug symbols":      {separateDebugFile, true},
	}

	for testName, testCase := range tests {
		name := testName
		tc := testCase
		t.Run(name, func(t *testing.T) {
			elfFile := getELF(tc.filePath, t)
			defer elfFile.Close()

			hasDWARF := pfelf.HasDWARFData(elfFile)

			if hasDWARF != tc.expectedResult {
				t.Fatalf("Expected %v but got %v", tc.expectedResult, hasDWARF)
			}
		})
	}
}

func TestGetSectionAddress(t *testing.T) {
	elfFile := getELF("testdata/fixed-address", t)
	defer elfFile.Close()

	// The fixed-address test executable has a section named `.coffee_section` at address 0xC0FFEE
	address, found, err := pfelf.GetSectionAddress(elfFile, ".coffee_section")
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Fatalf("unable to find .coffee_section")
	}
	expectedAddress := uint64(0xC0FFEE)
	if address != expectedAddress {
		t.Fatalf("expected address 0x%x, got 0x%x", expectedAddress, address)
	}

	// Try to find a section that does not exist
	_, found, err = pfelf.GetSectionAddress(elfFile, ".tea_section")
	if err != nil {
		t.Fatal(err)
	}
	if found {
		t.Fatalf("did not expect to find .tea_section")
	}
}

func TestGetBuildIDFromNotesFile(t *testing.T) {
	buildID, err := pfelf.GetBuildIDFromNotesFile("testdata/the_notorious_build_id")
	if err != nil {
		t.Fatal(err)
	}
	if buildID != hex.EncodeToString([]byte("_notorious_build_id_")) {
		t.Fatalf("got wrong buildID: %v", buildID)
	}
}

func TestGetKernelVersionBytes(t *testing.T) {
	files := []string{"testdata/kernel-image", "testdata/ubuntu-kernel-image"}
	for _, f := range files {
		f := f
		t.Run(f, func(t *testing.T) {
			elfFile := getELF(f, t)
			defer elfFile.Close()

			ver, err := pfelf.GetKernelVersionBytes(elfFile)
			if err != nil {
				t.Fatal(err)
			}
			versionString := string(ver)
			if versionString != "Linux version 1.2.3\n" {
				t.Fatalf("unexpected value: %v", versionString)
			}
		})
	}
}

func TestFilehandling(t *testing.T) {
	// The below hashes can be generated or checked with bash like:
	//  $ printf "\x7fELF\x00\x01\x02\x03\x04"|sha256sum
	//  39022213564b1d52549ebe535dfff027c618ab0a599d5e7c69ed4a2e1d3dd687  -
	tests := map[string]struct {
		data []byte
		id   libpf.FileID
		hash string
	}{
		"emptyFile": {
			data: []byte{},
			id:   libpf.NewFileID(0xe3b0c44298fc1c14, 0x9afbf4c8996fb924),
			hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		"simpleFile": {
			data: []byte{0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA},
			id:   libpf.NewFileID(0xc848e1013f9f04a9, 0xd63fa43ce7fd4af0),
			hash: "c848e1013f9f04a9d63fa43ce7fd4af035152c7c669a4a404b67107cee5f2e4e",
		},
		"ELF file": { // ELF file magic is 0x7f,'E','L','F'"
			data: []byte{0x7F, 'E', 'L', 'F', 0x00, 0x01, 0x2, 0x3, 0x4},
			id:   libpf.NewFileID(0xcaf6e5907166ac76, 0xeef618e5f7f59cd9),
			hash: "caf6e5907166ac76eef618e5f7f59cd98a02f0ab46acf413aa6a293a84fe1721",
		},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			fileName, err := libpf.WriteTempFile(testcase.data, "", name)
			if err != nil {
				t.Fatalf("Failed to write temporary file: %v", err)
			}
			defer os.Remove(fileName)

			fileID, err := pfelf.CalculateID(fileName)
			if err != nil {
				t.Fatalf("Failed to calculate executable ID: %v", err)
			}
			if fileID != testcase.id {
				t.Fatalf("Unexpected FileID. Expected %d, got %d", testcase.id, fileID)
			}

			hash, err := pfelf.CalculateIDString(fileName)
			if err != nil {
				t.Fatalf("Failed to generate hash of file: %v", err)
			}
			if hash != testcase.hash {
				t.Fatalf("Unexpected Hash. Expected %s, got %s", testcase.hash, hash)
			}
		})
	}
}

func assertSymbol(t *testing.T, symmap *libpf.SymbolMap, name libpf.SymbolName,
	expectedAddress libpf.SymbolValue) {
	sym, _ := symmap.LookupSymbol(name)
	if expectedAddress == libpf.SymbolValueInvalid {
		if sym != nil {
			t.Fatalf("symbol '%s', was unexpectedly found", name)
		}
	} else {
		if sym == nil {
			t.Fatalf("symbol '%s', was unexpectedly not found", name)
		}
		if sym.Address != expectedAddress {
			t.Fatalf("symbol '%s', expected address 0x%x, got 0x%x",
				name, expectedAddress, sym.Address)
		}
	}
}

func assertRevSymbol(t *testing.T, symmap *libpf.SymbolMap, addr libpf.SymbolValue,
	expectedName libpf.SymbolName, expectedOffset libpf.Address) {
	name, offs, ok := symmap.LookupByAddress(addr)
	if !ok {
		t.Fatalf("address '%x', unexpectedly has no name", addr)
	}
	if name != expectedName || expectedOffset != offs {
		t.Fatalf("address '%x', expected name %s+%d, got %s+%d",
			addr, expectedName, expectedOffset, name, offs)
	}
}

func TestSymbols(t *testing.T) {
	exePath, err := testsupport.WriteSharedLibrary()
	if err != nil {
		t.Fatalf("Failed to write test executable: %v", err)
	}
	defer os.Remove(exePath)

	ef, err := elf.Open(exePath)
	if err != nil {
		t.Fatalf("Failed to open test executable: %v", err)
	}
	defer ef.Close()

	syms, err := pfelf.GetDynamicSymbols(ef)
	if err != nil {
		t.Fatalf("Failed to get dynamic symbols: %v", err)
	}

	assertSymbol(t, syms, "func", 0x1000)
	assertSymbol(t, syms, "not_existent", libpf.SymbolValueInvalid)
	assertRevSymbol(t, syms, 0x1002, "func", 2)
}

func testGoBinary(t *testing.T, filename string, isGoExpected bool) {
	ef := getELF(filename, t)
	defer ef.Close()

	isGo, err := pfelf.IsGoBinary(ef)
	assert.Nil(t, err)
	assert.Equal(t, isGo, isGoExpected)
}

func TestIsGoBinary(t *testing.T) {
	testGoBinary(t, "testdata/go-binary", true)
	testGoBinary(t, "testdata/without-debug-syms", false)
}

func TestHasCodeSection(t *testing.T) {
	tests := map[string]struct {
		filePath       string
		expectedResult bool
	}{
		"ELF executable - no DWARF":   {withoutDebugSymsPath, true},
		"ELF executable - with DWARF": {withDebugSymsPath, true},
		"Separate debug symbols":      {separateDebugFile, false},
	}

	for testName, testCase := range tests {
		name := testName
		tc := testCase
		t.Run(name, func(t *testing.T) {
			elfFile := getELF(tc.filePath, t)
			defer elfFile.Close()

			hasCode := pfelf.HasCodeSection(elfFile)

			if hasCode != tc.expectedResult {
				t.Fatalf("Expected %v but got %v", tc.expectedResult, hasCode)
			}
		})
	}
}

func TestCalculateKernelFileID(t *testing.T) {
	buildID := "f8e1cf0f60558098edaec164ac7749df"
	fileID := pfelf.CalculateKernelFileID(buildID)
	expectedFileID, _ := libpf.FileIDFromString("026a2d6a60ee6b4eb8ec85adf2e76f4d")
	assert.Equal(t, expectedFileID, fileID)
}

func TestKernelFileIDToggleDebug(t *testing.T) {
	fileID, _ := libpf.FileIDFromString("026a2d6a60ee6b4eb8ec85adf2e76f4d")
	toggled := pfelf.KernelFileIDToggleDebug(fileID)
	expectedFileID, _ := libpf.FileIDFromString("b8ec85adf2e76f4d026a2d6a60ee6b4e")
	assert.Equal(t, expectedFileID, toggled)
}
