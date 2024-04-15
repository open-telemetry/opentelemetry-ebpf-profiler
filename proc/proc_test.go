/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package proc

import (
	"testing"

	"github.com/elastic/otel-profiling-agent/libpf"
)

func assertSymbol(t *testing.T, symmap *libpf.SymbolMap, name libpf.SymbolName,
	expectedAddress libpf.SymbolValue) {
	sym, err := symmap.LookupSymbol(name)
	if err != nil {
		t.Fatalf("symbol '%s', was unexpectedly not found: %v", name, err)
	}
	if sym.Address != expectedAddress {
		t.Fatalf("symbol '%s', expected address 0x%x, got 0x%x",
			name, expectedAddress, sym.Address)
	}
}

func TestParseKallSyms(t *testing.T) {
	// Check parsing as if we were non-root
	symmap, err := GetKallsyms("testdata/kallsyms_0")
	if symmap != nil || err == nil {
		t.Fatalf("expected an error because symbol address is 0")
	}

	// Check parsing invalid file
	symmap, err = GetKallsyms("testdata/kallsyms_invalid")
	if symmap != nil || err == nil {
		t.Fatalf("expected an error because file is invalid")
	}

	// Happy case
	symmap, err = GetKallsyms("testdata/kallsyms")
	if err != nil {
		t.Fatalf("error parsing kallsyms: %v", err)
	}

	assertSymbol(t, symmap, "cpu_tss_rw", 0x6000)
	assertSymbol(t, symmap, "hid_add_device", 0xffffffffc033e550)
}
