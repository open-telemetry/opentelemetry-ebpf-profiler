/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package elfunwindinfo

import (
	"debug/elf"
	"testing"

	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
)

// Go 1.2 spec Appendix: PC-Value Table Encoding example
func TestPcval(t *testing.T) {
	res := []struct {
		val int32
		pc  uint
	}{
		{0, 0x2019},
		{32, 0x206b},
		{40, 0x206d},
		{48, 0x2073},
		{40, 0x2074},
		{32, 0x209b},
		{0, 0x209c},
	}
	data := []byte{
		0x02, 0x19, 0x40, 0x52, 0x10, 0x02, 0x10, 0x06,
		0x0f, 0x01, 0x0f, 0x27, 0x3f, 0x01, 0x00}
	p := newPcval(data, 0x2000, 1)
	i := 0
	for ok := true; ok; ok = p.step() {
		t.Logf("Pcval %d, %x", p.val, p.pcEnd)
		if p.val != res[i].val || p.pcEnd != res[i].pc {
			t.Fatalf("Unexpected pcval %d, %x != %d, %x",
				p.val, p.pcEnd, res[i].val, res[i].pc)
		}
		i++
	}
	if i != len(res) {
		t.Fatalf("Table not decoded in full")
	}
}

// Pcval with sequence that would result in out-of-bound read
func TestPcvalInvalid(_ *testing.T) {
	data := []byte{0x81}
	p := newPcval(data, 0x2000, 1)
	for p.step() {
	}
}

// Some strategy tests
func TestGoStrategy(t *testing.T) {
	res := []struct {
		file     string
		strategy int
	}{
		{"foo.go", strategyFramePointer},
		{"foo.s", strategyDeltasWithoutRBP},
		{"go/src/crypto/elliptic/p256_asm.go", strategyDeltasWithRBP},
	}
	for _, x := range res {
		s := getSourceFileStrategy(elf.EM_X86_64, []byte(x.file))
		if s != x.strategy {
			t.Fatalf("File %v strategy %v != %v", x.file, s, x.strategy)
		}
	}
}

func TestParseGoPclntab(t *testing.T) {
	tests := map[string]struct {
		elfFile string
	}{
		// helloworld is a very basic Go binary without special build flags.
		"regular Go binary":       {elfFile: "testdata/helloworld"},
		"regular ARM64 Go binary": {elfFile: "testdata/helloworld.arm64"},
		// helloworld.pie is a Go binary that is build with PIE enabled.
		"PIE Go binary": {elfFile: "testdata/helloworld.pie"},
		// helloworld.stripped.pie is a Go binary that is build with PIE enabled and all debug
		// information stripped.
		"stripped PIE Go binary": {elfFile: "testdata/helloworld.stripped.pie"},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			deltas := sdtypes.StackDeltaArray{}
			filter := &extractionFilter{}

			ef, err := pfelf.Open(test.elfFile)
			if err != nil {
				t.Fatal(err)
			}
			if err := parseGoPclntab(ef, &deltas, filter); err != nil {
				t.Fatal(err)
			}
			if len(deltas) == 0 {
				t.Fatal("Failed to extract stack deltas")
			}
		})
	}
}
