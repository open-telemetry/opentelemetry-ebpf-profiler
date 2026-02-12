// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package oomwatcher

import (
	"testing"

	"github.com/parca-dev/oomprof/oomprof"
)

func TestPfelfReaderImplementsInterface(t *testing.T) {
	// Verify that pfelfReader implements oomprof.ELFReader
	var _ oomprof.ELFReader = &pfelfReader{}
}

func TestPfelfFileImplementsInterface(t *testing.T) {
	// Verify that pfelfFile implements oomprof.ELFFile
	var _ oomprof.ELFFile = &pfelfFile{}
}

func TestInit(t *testing.T) {
	// Verify that the global ELF reader is set
	reader := oomprof.GetELFReader()
	if reader == nil {
		t.Fatal("Expected global ELF reader to be set")
	}

	// Verify it's our implementation by checking the type
	if _, ok := reader.(*pfelfReader); !ok {
		t.Errorf("Expected global ELF reader to be *pfelfReader, got %T", reader)
	}
}

func TestPfelfReaderOpenAndRead(t *testing.T) {
	reader := &pfelfReader{}

	// Try to open the Go binary itself (should be a Go binary)
	file, err := reader.Open("/home/tpr/.gvm/gos/go1.25.1/bin/go")
	if err != nil {
		t.Skipf("Could not open Go binary for testing: %v", err)
	}
	defer file.Close()

	// Test GetBuildID
	buildID, err := file.GetBuildID()
	if err != nil {
		t.Logf("GetBuildID returned error (may be expected): %v", err)
	} else {
		t.Logf("Build ID: %s", buildID)
		if buildID == "" {
			t.Error("Expected non-empty build ID")
		}
	}

	// Test GoVersion
	goVersion, err := file.GoVersion()
	if err != nil {
		t.Fatalf("GoVersion failed: %v", err)
	}
	if goVersion == "" {
		t.Error("Expected non-empty Go version")
	}
	t.Logf("Go version: %s", goVersion)

	// Test LookupSymbol - try to find a common Go symbol
	symInfo, err := file.LookupSymbol("runtime.main")
	if err != nil {
		t.Logf("Could not find runtime.main symbol: %v", err)
	} else {
		t.Logf("Found symbol runtime.main at address 0x%x", symInfo.Address)
		if symInfo.Name != "runtime.main" {
			t.Errorf("Expected symbol name 'runtime.main', got '%s'", symInfo.Name)
		}
		if symInfo.Address == 0 {
			t.Error("Expected non-zero address for runtime.main")
		}
	}
}
