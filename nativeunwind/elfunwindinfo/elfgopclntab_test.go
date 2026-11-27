// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo

import (
	"bytes"
	"io"
	"math"
	"os"
	"strings"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/libpf/readatbuf"
	sdtypes "go.opentelemetry.io/ebpf-profiler/nativeunwind/stackdeltatypes"
	"go.opentelemetry.io/ebpf-profiler/testsupport"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Go 1.2 spec Appendix: PC-Value Table Encoding example. Each step returns
// the PC where a value starts to be in effect, along with that value.
func TestPcval(t *testing.T) {
	res := []struct {
		val int32
		pc  uint
	}{
		{0, 0},
		{32, 0x19},
		{40, 0x6b},
		{48, 0x6d},
		{40, 0x73},
		{32, 0x74},
		{0, 0x9b},
	}
	data := []byte{
		0x02, 0x19, 0x40, 0x52, 0x10, 0x02, 0x10, 0x06,
		0x0f, 0x01, 0x0f, 0x27, 0x3f, 0x01, 0x00}
	p := newPcvalDecoder(libpf.NewBytesView(data), 0, int64(len(data)), 1)
	i := 0
	for {
		pc, val, err := p.step()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		// Guard the indexing below: a regression that makes the table step
		// further than expected should fail here, not panic.
		require.Less(t, i, len(res))
		assert.Equal(t, res[i].val, val)
		assert.Equal(t, res[i].pc, pc)
		i++
	}
	assert.Equal(t, len(res), i)
}

// Pcval with sequence that would result in out-of-bound read. The truncated
// varint must be rejected rather than decoded as a zero delta: doing so would
// leave val at its -1 sentinel while reporting success.
func TestPcvalInvalid(t *testing.T) {
	data := []byte{0x81}
	p := newPcvalDecoder(libpf.NewBytesView(data), 0, int64(len(data)), 1)
	_, _, err := p.step()
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, int32(-1), p.val)
	// The decoder stays at the end of the data: a repeated step keeps
	// reporting the end of the table.
	_, _, err = p.step()
	require.ErrorIs(t, err, io.EOF)
	assert.Equal(t, int32(-1), p.val)
}

// TestNewPcvalEmpty verifies that a table with no decodable first entry is
// rejected, so that callers never see the -1 sentinel in val. The parse loops
// read val before their first step, so a sentinel would be emitted as unwind
// information: 7 on x86 (val+8) and -1 on arm64.
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
			p := newPcvalDecoder(libpf.NewBytesView(test.data), 0, int64(len(test.data)), 1)
			_, _, err := p.step()
			require.Error(t, err)
			assert.Equal(t, int32(-1), p.val)
		})
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

	var runtimeTextAddr uint64
	ef.VisitSymbols(func(sym libpf.Symbol) bool {
		if sym.Name == "runtime.text" {
			runtimeTextAddr = uint64(sym.Address)
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

// TestPcvalBounds verifies that an out-of-range pcval offset, which is
// untrusted data from the pclntab function descriptor, is rejected rather
// than reading out of bounds. The negative cases must not panic with "slice
// bounds out of range".
func TestPcvalBounds(t *testing.T) {
	data := []byte{0x02, 0x19, 0x00}
	for _, test := range []struct {
		name      string
		offs      int32
		outOfBnds bool
	}{
		{"negative", -1, true},
		{"minInt32", math.MinInt32, true},
		{"maxInt32", math.MaxInt32, false},
		// An offset of exactly len(pctab) or past it yields io.EOF from the
		// bounded reader rather than an out of range slice.
		{"atEnd", int32(len(data)), false},
		// In bounds, but pointing at the end-of-table marker.
		{"terminator", 2, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newPcvalDecoder(libpf.NewBytesView(data), 0, int64(len(data)), 1)
			p.reset(test.offs, 0)
			_, _, err := p.step()
			require.Error(t, err)
			if test.outOfBnds {
				assert.ErrorContains(t, err, "out of bounds")
			} else {
				assert.ErrorIs(t, err, io.EOF)
			}
		})
	}

	// A valid offset still decodes the table: the first entry starts at pc 0
	// with the value 0 in effect up to 0x19.
	p := newPcvalDecoder(libpf.NewBytesView(data), 0, int64(len(data)), 1)
	p.reset(0, 0)
	pc, val, err := p.step()
	require.NoError(t, err)
	assert.Equal(t, int32(0), val)
	assert.Equal(t, uint(0), pc)
}

// TestPcvalSentinel verifies that a table whose first entry steps
// successfully, but leaves val negative, is rejected. Rejecting truncated
// varints is not enough on its own: a non-canonical encoding of zero decodes
// fine, so the -1 sentinel survives a successful step and would be emitted as
// unwind information, as Param 7 on x86 (val+8) or -1 on arm64.
//
// The expected reason is asserted, not just that some error is returned, so
// that a case cannot silently start being caught by an earlier check and stop
// testing what its name says.
func TestPcvalSentinel(t *testing.T) {
	for _, test := range []struct {
		name    string
		pctab   []byte
		wantEOF bool
		wantErr string
	}{
		// 0x80 0x00 is a non-canonical encoding of zero, and thus decodes as
		// the end-of-table marker. Kept to pin that behavior: this is
		// rejected as an empty table, not by value.
		{"nonCanonicalZero", []byte{0x80, 0x00, 0x02, 0x00}, true, ""},
		// The same value, with the maximum padding getInt will consume before
		// the shift stops contributing.
		{"nonCanonicalZeroLong", []byte{0x80, 0x80, 0x80, 0x00, 0x02, 0x00}, true, ""},
		// A negative delta, taking val below the minimum valid value rather
		// than leaving it at the sentinel. Rejected by value, not by being
		// the sentinel.
		{"negativeDelta", []byte{0x03, 0x02, 0x00}, false, "is below 0"},
		// A canonical zero cannot be encoded as a leading 0x00, because that
		// byte is the end-of-table marker. That is precisely why the
		// non-canonical encoding above is the interesting case. Kept to pin
		// that behavior: this is rejected as an empty table, not by value.
		{"leadingTerminator", []byte{0x00, 0x02, 0x00}, true, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := newPcvalDecoder(libpf.NewBytesView(test.pctab), 0, int64(len(test.pctab)), 1)
			p.reset(0, 0)
			_, _, err := p.step()
			if test.wantEOF {
				assert.ErrorIs(t, err, io.EOF)
			} else {
				assert.ErrorContains(t, err, test.wantErr)
			}
		})
	}
}

// TestSymbolizeBorrowedReader verifies that symbolization shares an
// underlying readatbuf reader instead of creating a new cache, and does not
// release it on Close.
func TestSymbolizeBorrowedReader(t *testing.T) {
	testsupport.RequireGeneratedTestFile(t, "testdata/helloworld")
	f, err := os.Open("testdata/helloworld")
	require.NoError(t, err)
	defer f.Close()

	// The File reads through a cached reader: NewGopclntab must share it
	// instead of creating a new cache.
	borrowed, err := readatbuf.New(f, 1024, 4)
	require.NoError(t, err)
	ef, err := pfelf.NewFile(borrowed, 0, false)
	require.NoError(t, err)

	g, err := NewGopclntab(ef)
	require.NoError(t, err)

	// Resolve main.main by name, and symbolize it.
	syms := []libpf.Symbol{{Name: "main.main"}}
	require.NoError(t, g.LookupSymbols(syms))
	require.NotZero(t, syms[0].Address)

	sourceFile, line, funcName := g.Symbolize(uint64(syms[0].Address))
	assert.Equal(t, "main.main", funcName.String())
	assert.NotZero(t, line)
	assert.NotEqual(t, libpf.NullString, sourceFile)

	// The underlying cached reader is shared, and is not owned.
	assert.Same(t, borrowed, g.readerAt)

	// Close drops the reference, but leaves the shared reader functional.
	require.NoError(t, g.Close())
	assert.Nil(t, g.readerAt)
	var buf [4]byte
	_, err = borrowed.ReadAt(buf[:], 0)
	require.NoError(t, err)
}

// TestSymbolizeAfterFileClose verifies that Gopclntab keeps the backing
// pfelf.File's underlying reader open via Take, and can symbolize lazily
// after the File itself has been closed.
func TestSymbolizeAfterFileClose(t *testing.T) {
	testsupport.RequireGeneratedTestFile(t, "testdata/helloworld")
	ef, err := pfelf.Open("testdata/helloworld")
	require.NoError(t, err)

	g, err := NewGopclntab(ef)
	require.NoError(t, err)
	defer g.Close()

	// Resolve main.main by name while the File is open.
	syms := []libpf.Symbol{{Name: "main.main"}}
	require.NoError(t, g.LookupSymbols(syms))
	require.NotZero(t, syms[0].Address)

	// Close the File; the Gopclntab holds a reference on the reader.
	require.NoError(t, ef.Close())

	// Symbolization still works: the reference keeps the reader open, and
	// the lazily initialized caches read through it.
	sourceFile, line, funcName := g.Symbolize(uint64(syms[0].Address))
	assert.Equal(t, "main.main", funcName.String())
	assert.NotZero(t, line)
	assert.NotEqual(t, libpf.NullString, sourceFile)

	// Repeated lookups are served from the caches.
	sf, ln, fn := g.Symbolize(uint64(syms[0].Address))
	assert.Equal(t, sourceFile, sf)
	assert.Equal(t, ln, line)
	assert.Equal(t, fn, funcName)
}

// TestNewGopclntabErrorReleasesRef verifies that a failed NewGopclntab does
// not leak the reference taken on the backing pfelf.File: after File.Close,
// the owned reader must be closed.
func TestNewGopclntabErrorReleasesRef(t *testing.T) {
	testsupport.RequireGeneratedTestFile(t, "testdata/helloworld")
	data, err := os.ReadFile("testdata/helloworld")
	require.NoError(t, err)

	// Find the .gopclntab section offset from a valid File.
	ef, err := pfelf.Open("testdata/helloworld")
	require.NoError(t, err)
	sec := ef.Section(".gopclntab")
	require.NotNil(t, sec)
	require.NoError(t, ef.Close())

	// Corrupt the pclntab magic so NewGopclntab fails after locating the
	// section.
	data[sec.Offset] = 0xab

	tracker := &closeTracker{ReaderAt: bytes.NewReader(data)}
	bad, err := pfelf.NewFileOwned(tracker)
	require.NoError(t, err)

	_, err = NewGopclntab(bad)
	require.ErrorContains(t, err, "unsupported header")

	require.NoError(t, bad.Close())
	assert.Equal(t, 1, tracker.closed, "owned reader not closed")
}

// closeTracker counts Close calls on a ReadAtCloser.
type closeTracker struct {
	io.ReaderAt
	closed int
}

func (c *closeTracker) Close() error {
	c.closed++
	return nil
}

// TestSymbolizeReal symbolizes functions from real Go binaries, exercising
// the sparse index, the file read caches and the function data LRU.
func TestSymbolizeReal(t *testing.T) {
	tests := map[string]struct {
		elfFile string
	}{
		"regular Go binary":       {elfFile: "testdata/helloworld"},
		"regular ARM64 Go binary": {elfFile: "testdata/helloworld.arm64"},
		"PIE Go binary":           {elfFile: "testdata/helloworld.pie"},
		"stripped PIE Go binary":  {elfFile: "testdata/helloworld.stripped.pie"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			testsupport.RequireGeneratedTestFile(t, test.elfFile)
			ef, err := pfelf.Open(test.elfFile)
			require.NoError(t, err)

			g, err := NewGopclntab(ef)
			require.NoError(t, err)
			defer g.Close()

			// Resolve main.main by name, and symbolize it.
			syms := []libpf.Symbol{{Name: "main.main"}}
			require.NoError(t, g.LookupSymbols(syms))
			require.NotZero(t, syms[0].Address)
			require.NotZero(t, syms[0].Size)

			// Symbolize the start of main.main. Do not use a pc in the
			// middle of the function: for this test binary the middle is
			// attributed to an inlined function from another source file.
			at := uint64(syms[0].Address)
			sourceFile, line, funcName := g.Symbolize(at)
			assert.Equal(t, "main.main", funcName.String())
			assert.True(t, strings.HasSuffix(sourceFile.String(), "helloworld.go"), sourceFile.String())
			assert.NotZero(t, line)

			// Repeat the lookup; it must be served from the function data
			// cache with identical results.
			sf, ln, fn := g.Symbolize(at)
			assert.Equal(t, sourceFile, sf)
			assert.Equal(t, line, ln)
			assert.Equal(t, funcName, fn)

			// Symbolize the start and end of every function; the function
			// name must always resolve.
			_, _, err = g.walkFuncMap(func(pc, endPc uint64, fun *pclntabFunc) error {
				for _, at := range []uint64{pc, endPc - 1} {
					_, _, funcName := g.Symbolize(uint64(at))
					assert.NotEqual(t, libpf.NullString, funcName, "pc %#x", at)
				}
				return nil
			})
			require.NoError(t, err)
		})
	}
}
