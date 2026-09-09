// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo

import (
	"fmt"
	"math"
	"testing"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/testsupport"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		assert.Equal(t, res[i].val, p.val)
		assert.Equal(t, res[i].pc, p.pcEnd)
		i++
	}
	assert.Equal(t, len(res), i)
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
		file   string
		result strategy
	}{
		{"foo.go", strategyUnknown},
		{"foo.s", strategyDeltasWithoutFrame},
		{"go/src/crypto/elliptic/p256_asm.go", strategyDeltasWithFrame},
	}
	for _, x := range res {
		s := getSourceFileStrategyX86(x.file)
		assert.Equal(t, x.result, s)
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
		t.Run(name, func(t *testing.T) {
			testsupport.RequireGeneratedTestFile(t, test.elfFile)
			ef, err := pfelf.Open(test.elfFile)
			require.NoError(t, err)

			ee := elfExtractor{
				file:      ef,
				hooks:     &extractionFilter{},
				intervals: &sdtypes.IntervalData{},
			}
			err = ee.parseGoPclntab()
			require.NoError(t, err)
			assert.NotEmpty(t, ee.intervals.Blocks)
		})
	}
}

func TestTextStart(t *testing.T) {
	testsupport.RequireGeneratedTestFile(t, "testdata/helloworld.linkexternal")
	ef, err := pfelf.Open("testdata/helloworld.linkexternal")
	require.NoError(t, err)
	defer ef.Close()

	var runtimeTextAddr uintptr
	ef.VisitSymbols(func(sym libpf.Symbol) bool {
		if sym.Name == "runtime.text" {
			runtimeTextAddr = uintptr(sym.Address)
			return false
		}
		return true
	})
	require.NotZero(t, runtimeTextAddr)

	g, err := NewGopclntab(ef)
	require.NoError(t, err)
	require.NotNil(t, g)
	defer g.Close()

	require.Equal(t, runtimeTextAddr, g.textStart)

	// stripped binary should have the same text start
	testsupport.RequireGeneratedTestFile(t, "testdata/helloworld.linkexternal.stripped")
	efStripped, err := pfelf.Open("testdata/helloworld.linkexternal.stripped")
	require.NoError(t, err)
	defer efStripped.Close()
	gStripped, err := NewGopclntab(efStripped)
	require.NoError(t, err)
	require.NotNil(t, gStripped)
	defer gStripped.Close()

	require.Equal(t, runtimeTextAddr, gStripped.textStart)
}

// TestGetPcvalBounds verifies that an out-of-range pcval offset, which is
// untrusted data from the pclntab function descriptor, does not slice out
// of bounds. The negative cases must not panic with "slice bounds out of
// range".
func TestGetPcvalBounds(t *testing.T) {
	g := &Gopclntab{
		pctab:   []byte{0x02, 0x19, 0x00},
		quantum: 1,
	}
	for _, test := range []struct {
		name string
		offs int32
	}{
		{"negative", -1},
		{"minInt32", math.MinInt32},
		{"pastEnd", int32(len(g.pctab) + 1)},
		{"maxInt32", math.MaxInt32},
		{"atEnd", int32(len(g.pctab))},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := g.getPcval(test.offs, 0x2000)
			// An empty table steps to a stop immediately.
			assert.False(t, p.step())
		})
	}

	// A valid offset still decodes the table.
	p := g.getPcval(0, 0x2000)
	assert.Equal(t, int32(0), p.val)
	assert.Equal(t, uint(0x2019), p.pcEnd)
}

// TestGetFuncOverflow verifies that a function offset near the top of the
// address space does not wrap around the bounds check in getFunc. funcOff is
// read verbatim from the file as a 64-bit value for pre-Go1.18 pclntab.
// Check that these cases don't panic with "index out of range", and that the
// accepted ones return a pclntabFunc that fits in the table.
func TestGetFuncOverflow(t *testing.T) {
	// getFunc skips over the function start PC, whose width depends on the
	// pclntab version, before returning the pclntabFunc that follows it.
	// funSize has to account for both parts.
	for _, version := range []uint8{go1_16, go1_18, go1_20} {
		t.Run(fmt.Sprintf("version%d", version), func(t *testing.T) {
			g := &Gopclntab{
				functab: make([]byte, 128),
				version: version,
				ptrSize: 8,
			}
			if version >= go1_18 {
				g.funSize = 4 + uint8(unsafe.Sizeof(pclntabFunc{}))
			} else {
				g.funSize = g.ptrSize + uint8(unsafe.Sizeof(pclntabFunc{}))
			}
			tabStart := uintptr(unsafe.Pointer(&g.functab[0]))
			tabEnd := tabStart + uintptr(len(g.functab))

			for _, test := range []struct {
				name    string
				funcOff uintptr
			}{
				{"maxUintptr", ^uintptr(0)},
				{"wrapsToZero", ^uintptr(0) - uintptr(g.funSize) + 1},
				{"justPastEnd", uintptr(len(g.functab))},
				{"lastByte", uintptr(len(g.functab) - 1)},
				{"oneTooFar", uintptr(len(g.functab)) - uintptr(g.funSize) + 1},
			} {
				t.Run(test.name, func(t *testing.T) {
					pc, fun := g.getFunc(test.funcOff)
					assert.Zero(t, pc)
					assert.Nil(t, fun)
				})
			}

			// The last offset that still fits a full function descriptor is
			// accepted, and the descriptor ends exactly at the end of the
			// table: the bound is tight, and never returns a pclntabFunc
			// reaching past the mapping.
			lastValid := uintptr(len(g.functab)) - uintptr(g.funSize)
			_, fun := g.getFunc(lastValid)
			require.NotNil(t, fun)
			funEnd := uintptr(unsafe.Pointer(fun)) + unsafe.Sizeof(pclntabFunc{})
			assert.Equal(t, tabEnd, funEnd)

			// An in-range offset is still accepted, and stays in bounds.
			_, fun = g.getFunc(0)
			require.NotNil(t, fun)
			funEnd = uintptr(unsafe.Pointer(fun)) + unsafe.Sizeof(pclntabFunc{})
			assert.GreaterOrEqual(t, tabEnd, funEnd)
		})
	}
}
