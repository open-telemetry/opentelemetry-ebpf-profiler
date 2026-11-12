// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo

import (
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"reflect"
	"runtime"
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
	p, ok := newPcval(data, 0x2000, 1)
	require.True(t, ok)
	i := 0
	for ; ok; ok = p.step() {
		t.Logf("Pcval %d, %x", p.val, p.pcEnd)
		// Guard the indexing below: a regression that makes the table step
		// further than expected should fail here, not panic.
		require.Less(t, i, len(res))
		assert.Equal(t, res[i].val, p.val)
		assert.Equal(t, res[i].pc, p.pcEnd)
		i++
	}
	assert.Equal(t, len(res), i)
}

// Pcval with sequence that would result in out-of-bound read. The truncated
// varint must be rejected rather than decoded as a zero delta: doing so would
// leave val at its -1 sentinel while reporting success.
func TestPcvalInvalid(t *testing.T) {
	data := []byte{0x81}
	p, ok := newPcval(data, 0x2000, 1)
	assert.False(t, ok)
	assert.Equal(t, int32(-1), p.val)
	assert.False(t, p.step())
}

// TestNewPcvalEmpty verifies that newPcval reports failure when the table has
// no decodable first entry, so that callers never see the -1 sentinel in val.
// The parse loops read val before their first step, so a sentinel would be
// emitted as unwind information: 7 on x86 (val+8) and -1 on arm64.
func TestNewPcvalEmpty(t *testing.T) {
	for _, test := range []struct {
		name string
		data []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"terminator", []byte{0x00}},
		{"terminatorThenData", []byte{0x00, 0x02, 0x19}},
		{"truncatedFirstVarint", []byte{0x81}},
		{"truncatedSecondVarint", []byte{0x02}},
		{"truncatedContinuation", []byte{0x02, 0x81}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p, ok := newPcval(test.data, 0x2000, 1)
			assert.False(t, ok)
			assert.Equal(t, int32(-1), p.val)
		})
	}
}

// The first entry can keep the initial -1, encoded as a zero value delta.
func TestMapInlineIndex(t *testing.T) {
	g := Gopclntab{pctab: []byte{0x00, 0x00, 0x05, 0x02, 0x03, 0x00, 0x00}, quantum: 1}
	assert.Equal(t, int32(-1), g.mapInlineIndex(1, 0x10, 0x12))
	assert.Equal(t, int32(0), g.mapInlineIndex(1, 0x10, 0x16))
	assert.Equal(t, int32(-1), g.mapInlineIndex(1, 0x10, 0x18))
	// Offset zero is the empty table; the other offsets have no complete entry.
	assert.Equal(t, int32(-1), g.mapInlineIndex(0, 0x10, 0x12))
	assert.Equal(t, int32(-1), g.mapInlineIndex(6, 0x10, 0x10))
	assert.Equal(t, int32(-1), g.mapInlineIndex(7, 0x10, 0x10))
}

func TestFindGoFunc(t *testing.T) {
	const pclntabAddr, gofuncAddr = uintptr(0x1000), uintptr(0x2000)
	const gofuncOffset = 320
	g := Gopclntab{funcnameOffset: 0x80, cuOffset: 0x100}
	record := make([]byte, gofuncOffset+8)
	binary.LittleEndian.PutUint64(record, uint64(pclntabAddr))
	binary.LittleEndian.PutUint64(record[8:], uint64(pclntabAddr+g.funcnameOffset))
	binary.LittleEndian.PutUint64(record[32:], uint64(pclntabAddr+g.cuOffset))
	binary.LittleEndian.PutUint64(record[gofuncOffset:], uint64(gofuncAddr))
	assert.Equal(t, gofuncAddr, g.findGoFunc(record, pclntabAddr, gofuncOffset))

	// A matching header address alone is insufficient; keep searching.
	withFalseMatch := make([]byte, 8)
	binary.LittleEndian.PutUint64(withFalseMatch, uint64(pclntabAddr))
	withFalseMatch = append(withFalseMatch, record...)
	assert.Equal(t, gofuncAddr, g.findGoFunc(withFalseMatch, pclntabAddr, gofuncOffset))

	for _, test := range []struct {
		name   string
		data   []byte
		offset int
	}{
		{"empty", nil, gofuncOffset},
		{"truncated", record[:len(record)-1], gofuncOffset},
		{"unaligned", append([]byte{0}, record...), gofuncOffset},
		{"negativeOffset", record, -1},
		{"offsetBeforePrefix", record, 24},
		{"offsetPastEnd", record, len(record)},
	} {
		t.Run(test.name, func(t *testing.T) {
			assert.Zero(t, g.findGoFunc(test.data, pclntabAddr, test.offset))
		})
	}
	for _, pointerOff := range []int{8, 32} {
		t.Run(fmt.Sprintf("wrongPointer%d", pointerOff), func(t *testing.T) {
			bad := append([]byte(nil), record...)
			binary.LittleEndian.PutUint64(bad[pointerOff:], 0)
			assert.Zero(t, g.findGoFunc(bad, pclntabAddr, gofuncOffset))
		})
	}
}

func TestGoFuncOffset(t *testing.T) {
	for _, test := range []struct {
		version   uint8
		goVersion string
		want      int
	}{
		{go1_18, "go1.18", 304},
		{go1_18, "go1.19.13", 304},
		{go1_18, "", 304}, // The header identifies this layout without build info.
		{go1_20, "go1.20", 320},
		{go1_20, "go1.26.0", 320},
		{go1_20, "go1.27beta1", 344},
		{go1_20, "go1.27rc1", 344},
		{go1_20, "go1.27.0", 344},
		{go1_20, "go1.28beta1", 0},
		{go1_20, "go1.28rc1", 0},
		{go1_20, "go1.28.0", 0},
		{go1_20, "", 0},
		{go1_20, "devel go1.27-abcdef", 0},
		{go1_16, "go1.16.15", 0},
		{goInvalid, "go1.27.0", 0},
	} {
		t.Run(fmt.Sprintf("header%d/%s", test.version, test.goVersion), func(t *testing.T) {
			g := Gopclntab{version: test.version}
			assert.Equal(t, test.want, g.goFuncOffset(test.goVersion))
		})
	}
}

func TestGetInlinedCall(t *testing.T) {
	for _, test := range []struct {
		name    string
		version uint8
		tree    []byte
	}{
		{"Go116", go1_16, []byte{
			0, 0, 0, 0, // parent, funcID, padding
			0, 0, 0, 0, // file
			0, 0, 0, 0, // line
			1, 0, 0, 0, // name offset
			42, 0, 0, 0, // parent PC
		}},
		{"Go120", go1_20, []byte{
			0, 0, 0, 0, // funcID, padding
			1, 0, 0, 0, // name offset
			42, 0, 0, 0, // parent PC
			7, 0, 0, 0, // start line
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := Gopclntab{version: test.version, funcnametab: []byte("\x00leaf\x00")}
			name, parentPc := g.getInlinedCall(test.tree, 0)
			assert.Equal(t, "leaf", name)
			assert.Equal(t, 42, parentPc)
		})
	}
}

type symbolizedFrame struct {
	function, file string
	line           int
}

//go:noinline
func callers() []uintptr {
	pcs := make([]uintptr, 32)
	return pcs[:runtime.Callers(2, pcs)]
}

// These helpers are small enough to be inlined into inlineRoot.
func inlinedLeaf() []uintptr   { return callers() }
func inlinedMiddle() []uintptr { return inlinedLeaf() }

//go:noinline
func inlineRoot() []uintptr { return inlinedMiddle() }

func TestSymbolizeInlined(t *testing.T) {
	pcs := inlineRoot()
	require.GreaterOrEqual(t, len(pcs), 4)
	rootPc := reflect.ValueOf(inlineRoot).Pointer()
	if runtime.FuncForPC(pcs[0]).Entry() != rootPc {
		t.Skip("test functions were not inlined")
	}
	var want []symbolizedFrame
	runtimeFrames := runtime.CallersFrames(pcs)
	for len(want) < 4 {
		frame, more := runtimeFrames.Next()
		want = append(want, symbolizedFrame{frame.Function, frame.File, frame.Line})
		if len(want) < 4 {
			require.True(t, more)
		}
	}

	executable, err := os.Executable()
	require.NoError(t, err)
	ef, err := pfelf.Open(executable)
	require.NoError(t, err)
	defer ef.Close()
	g, err := NewGopclntab(ef)
	require.NoError(t, err)
	defer g.Close()

	root, err := g.LookupSymbol(libpf.SymbolName(want[2].function))
	require.NoError(t, err)
	loadBias := rootPc - uintptr(root.Address)
	symbolize := func(pc uintptr) []symbolizedFrame {
		var frames []symbolizedFrame
		ok := g.SymbolizeInlined(pc-loadBias-1, func(file string, line uint, name string) {
			frames = append(frames, symbolizedFrame{name, file, int(line)})
		})
		require.True(t, ok)
		return frames
	}
	assert.Equal(t, want[:3], symbolize(pcs[0]))
	assert.Equal(t, want[3:], symbolize(pcs[3]))

	// Symbolize retains the containing function with the innermost source line.
	file, line, name := g.Symbolize(pcs[0] - loadBias - 1)
	outer := symbolizedFrame{want[2].function, want[0].file, want[0].line}
	assert.Equal(t, symbolizedFrame{name, file, int(line)}, outer)
	assert.False(t, g.SymbolizeInlined(0, func(string, uint, string) {
		t.Fatal("unexpected frame")
	}))

	pc := pcs[0] - loadBias - 1
	funcIndex, funcPc, funcOff, fun := g.findFunc(pc)
	require.NotNil(t, fun)
	funcEnd, _ := g.getFuncMapEntry(funcIndex + 1)
	indexTable, tree := g.getInlineTree(funcOff, fun)
	require.NotEmpty(t, tree)
	leafIndex := g.mapInlineIndex(indexTable, uint(funcPc), uint(pc))
	require.GreaterOrEqual(t, leafIndex, int32(0))
	_, parentPc := g.getInlinedCall(tree, leafIndex)
	middleIndex := g.mapInlineIndex(indexTable, uint(funcPc), uint(funcPc)+uint(parentPc))
	require.GreaterOrEqual(t, middleIndex, int32(0))
	require.NotEqual(t, leafIndex, middleIndex)
	entrySize := int(unsafe.Sizeof(inlinedCall116{}))
	nameOff := int(unsafe.Offsetof(inlinedCall116{}.nameOff))
	parentOff := int(unsafe.Offsetof(inlinedCall116{}.parentPc))
	if g.version >= go1_20 {
		entrySize = int(unsafe.Sizeof(inlinedCall120{}))
		nameOff = int(unsafe.Offsetof(inlinedCall120{}.nameOff))
		parentOff = int(unsafe.Offsetof(inlinedCall120{}.parentPc))
	}
	for _, test := range []struct {
		name   string
		index  int32
		field  int
		value  uint32
		frames int
	}{
		{"invalidName", leafIndex, nameOff, ^uint32(0), 1},
		{"negativeParent", leafIndex, parentOff, ^uint32(0), 1},
		{"parentOutsideFunction", leafIndex, parentOff, uint32(funcEnd - funcPc), 1},
		{"selfReference", leafIndex, parentOff, uint32(pc - funcPc), 1},
		{"twoEntryCycle", middleIndex, parentOff, uint32(pc - funcPc), maxInlineDepth + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			corrupt := *g
			corrupt.funcdata = append([]byte(nil), g.funcdata...)
			field := len(g.funcdata) - len(tree) + int(test.index)*entrySize + test.field
			binary.LittleEndian.PutUint32(corrupt.funcdata[field:], test.value)
			var got []symbolizedFrame
			require.True(t, corrupt.SymbolizeInlined(pc, func(file string, line uint, name string) {
				got = append(got, symbolizedFrame{name, file, int(line)})
			}))
			require.Len(t, got, test.frames)
			assert.Equal(t, outer.function, got[len(got)-1].function)
		})
	}

	// Missing inline data falls back to the same single-frame result.
	g.funcdata = nil
	assert.Equal(t, []symbolizedFrame{outer}, symbolize(pcs[0]))
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
// untrusted data from the pclntab function descriptor, is rejected rather than
// slicing out of bounds. The negative cases must not panic with "slice bounds
// out of range".
func TestGetPcvalBounds(t *testing.T) {
	g := &Gopclntab{
		pctab:   []byte{0x02, 0x19, 0x00},
		quantum: 1,
	}
	for _, test := range []struct {
		name    string
		offs    int32
		wantErr string
	}{
		{"negative", -1, "out of bounds"},
		{"minInt32", math.MinInt32, "out of bounds"},
		{"pastEnd", int32(len(g.pctab) + 1), "out of bounds"},
		{"maxInt32", math.MaxInt32, "out of bounds"},
		// An offset of exactly len(pctab) yields an empty table rather than an
		// out of range slice, so it has to be caught by the bounds check and
		// not by the empty table check further down.
		{"atEnd", int32(len(g.pctab)), "out of bounds"},
		// In bounds, but pointing at the end-of-table marker.
		{"terminator", 2, "has no valid first entry"},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := g.getPcval(test.offs, 0x2000)
			require.ErrorContains(t, err, test.wantErr)
		})
	}

	// A valid offset still decodes the table.
	p, err := g.getPcval(0, 0x2000)
	require.NoError(t, err)
	assert.Equal(t, int32(0), p.val)
	assert.Equal(t, uint(0x2019), p.pcEnd)
}

// TestGetPcvalSentinel verifies that a table whose first entry steps
// successfully, but leaves val negative, is rejected. Rejecting truncated
// varints is not enough on its own: a non-canonical encoding of zero decodes
// fine, so the -1 sentinel survives a successful step and would be emitted as
// unwind information, as Param 7 on x86 (val+8) or -1 on arm64.
//
// The expected reason is asserted, not just that some error is returned, so
// that a case cannot silently start being caught by an earlier check and stop
// testing what its name says.
func TestGetPcvalSentinel(t *testing.T) {
	for _, test := range []struct {
		name    string
		pctab   []byte
		wantErr string
	}{
		// 0x80 0x00 is a non-canonical encoding of 0, then a pc delta of 2.
		// The value is unchanged, so val is still the sentinel, but unlike a
		// truncated table this steps successfully.
		{"nonCanonicalZero", []byte{0x80, 0x00, 0x02, 0x00},
			"starts with negative value -1"},
		// The same value, with the maximum padding getInt will consume before
		// the shift stops contributing.
		{"nonCanonicalZeroLong", []byte{0x80, 0x80, 0x80, 0x00, 0x02, 0x00},
			"starts with negative value -1"},
		// A negative delta, taking val below the sentinel rather than leaving
		// it there. Rejected by value, not by being the sentinel.
		{"negativeDelta", []byte{0x03, 0x02, 0x00},
			"starts with negative value -3"},
		// A canonical zero cannot be encoded as a leading 0x00, because that
		// byte is the end-of-table marker. That is precisely why the
		// non-canonical encoding above is the interesting case. Kept to pin
		// that behavior: this is rejected as an empty table, not by value.
		{"leadingTerminator", []byte{0x00, 0x02, 0x00},
			"has no valid first entry"},
	} {
		t.Run(test.name, func(t *testing.T) {
			g := &Gopclntab{pctab: test.pctab, quantum: 1}
			_, err := g.getPcval(0, 0x2000)
			require.ErrorContains(t, err, test.wantErr)
		})
	}
}

// TestGetFuncOverflow verifies that a function offset near the top of the
// address space does not wrap around the bounds check in getFunc. funcOff is
// read verbatim from the file as a 64-bit value for pre-Go1.18 pclntab.
// Check that these cases don't panic with "index out of range", and that the
// accepted ones return a pclntabFunc that fits in the table.
//
// go1_2 is not covered because NewGopclntab rejects it as an unsupported
// header, so getFunc is unreachable for it.
func TestGetFuncOverflow(t *testing.T) {
	// getFunc skips over the function start PC, whose width depends on the
	// pclntab version, before returning the pclntabFunc that follows it.
	// funSize has to account for both parts. This mirrors how NewGopclntab
	// sets funSize; the test builds the struct directly, so it covers getFunc
	// rather than that assignment, which real binaries exercise.
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
