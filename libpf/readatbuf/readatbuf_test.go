// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package readatbuf_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/readatbuf"
	"go.opentelemetry.io/ebpf-profiler/testsupport"
)

func testVariant(t *testing.T, fileSize, granularity, cacheSize uint) {
	t.Helper()
	file := testsupport.GenerateTestInputFile(255, fileSize)
	rawReader := bytes.NewReader(file)
	cachingReader, err := readatbuf.New(rawReader, granularity, cacheSize)
	require.NoError(t, err)
	testsupport.ValidateReadAtWrapperTransparency(t, 10000, file, cachingReader)
}

func TestCaching(t *testing.T) {
	testVariant(t, 1024, 64, 1)
	testVariant(t, 1346, 11, 55)
	testVariant(t, 889, 34, 111)
}

func TestOutOfBoundsTail(t *testing.T) {
	buf := bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	r, err := readatbuf.New(buf, 5, 10)
	require.NoError(t, err)
	b := make([]byte, 1)
	for i := range int64(32) {
		_, err = r.ReadAt(b, i)
		if i > 7 {
			require.ErrorIs(t, err, io.EOF)
		} else {
			require.NoError(t, err)
		}
	}
}

func TestViewAt(t *testing.T) {
	file := testsupport.GenerateTestInputFile(255, 1000)
	rawReader := bytes.NewReader(file)
	r, err := readatbuf.New(rawReader, 64, 4)
	require.NoError(t, err)

	// View at the start of a page.
	view, err := r.ViewAt(0, 1)
	require.NoError(t, err)
	require.Equal(t, file[:64], view)

	// View at an unaligned offset: maximal view extends to the page end.
	view, err = r.ViewAt(10, 10)
	require.NoError(t, err)
	require.Equal(t, file[10:64], view)

	// Past the end.
	view, err = r.ViewAt(1024, 1)
	require.ErrorIs(t, err, io.EOF)
	require.Nil(t, view)

	// Truncated last page: view within the page end is fine.
	view, err = r.ViewAt(990, 1)
	require.NoError(t, err)
	require.Equal(t, file[990:1000], view)

	// minLen extending beyond the truncated page end.
	_, err = r.ViewAt(990, 11)
	require.ErrorIs(t, err, io.EOF)

	// Straddling a page boundary.
	view, err = r.ViewAt(60, 5)
	require.ErrorIs(t, err, libpf.ErrNotContiguous)
	require.Nil(t, view)

	// minLen larger than the page size.
	_, err = r.ViewAt(0, 65)
	require.ErrorIs(t, err, libpf.ErrNotContiguous)

	// Negative offset.
	_, err = r.ViewAt(-1, 1)
	require.Error(t, err)

	// Non-positive minLen is treated as one.
	view, err = r.ViewAt(32, 0)
	require.NoError(t, err)
	require.Equal(t, file[32:64], view)
}

func TestViewAtNoPollution(t *testing.T) {
	// ErrNotContiguous must be determinable without any I/O and without
	// populating the cache.
	file := testsupport.GenerateTestInputFile(255, 1024)
	r, err := readatbuf.New(bytes.NewReader(file), 64, 4)
	require.NoError(t, err)

	stats := r.Statistics()
	for i := range 64 {
		_, err := r.ViewAt(int64(i), 128)
		require.ErrorIs(t, err, libpf.ErrNotContiguous)
	}
	require.Equal(t, stats, r.Statistics())
}

func TestViewAtMatchesReadAt(t *testing.T) {
	file := testsupport.GenerateTestInputFile(255, 2048)
	r, err := readatbuf.New(bytes.NewReader(file), 64, 4)
	require.NoError(t, err)

	for _, off := range []int64{0, 1, 63, 64, 65, 1975, 2047} {
		view, err := r.ViewAt(off, 1)
		require.NoError(t, err)
		expected := file[off:min(int64(len(file)), off+64-int64(off%64))]
		require.Equal(t, expected, view)
	}
}

func TestViewAtPinProtectsFromEviction(t *testing.T) {
	// A page aliased by an outstanding view must not be pooled on eviction:
	// even if the cache evicts it, the view stays valid, and the data is
	// re-read on the next access.
	file := testsupport.GenerateTestInputFile(255, 2048)
	r, err := readatbuf.New(bytes.NewReader(file), 64, 1)
	require.NoError(t, err)

	view, err := r.ViewAt(0, 1)
	require.NoError(t, err)
	require.Equal(t, file[:64], view)

	// Force page-ins and evictions through small ReadAt calls.
	buf := make([]byte, 16)
	for page := int64(1); page < 32; page++ {
		_, err = r.ReadAt(buf, page*64)
		require.NoError(t, err)
	}

	// The view must still hold the original, unmodified data.
	require.Equal(t, file[:64], view)

	// The cache must remain transparent.
	again, err := r.ViewAt(0, 1)
	require.NoError(t, err)
	require.Equal(t, file[:64], again)
}

func TestPinAtRefcountAndEviction(t *testing.T) {
	file := testsupport.GenerateTestInputFile(255, 4096)
	r, err := readatbuf.New(bytes.NewReader(file), 64, 4)
	require.NoError(t, err)

	// Two pins on the same page.
	view1, err := r.PinAt(0, 1)
	require.NoError(t, err)
	view2, err := r.PinAt(10, 1)
	require.NoError(t, err)

	// Force evictions through small reads on other pages.
	buf := make([]byte, 16)
	for page := int64(1); page < 64; page++ {
		_, err = r.ReadAt(buf, page*64)
		require.NoError(t, err)
	}
	require.Equal(t, file[0:64], view1)
	require.Equal(t, file[10:64], view2)

	// Unpin one: the other pin still protects the page.
	r.UnpinAt(0)
	require.Equal(t, file[10:64], view2)

	// Unpin the other: the page becomes evictable and poolable again.
	r.UnpinAt(10)

	// UnpinAt on absent or unpinned pages is a no-op.
	r.UnpinAt(0)
	r.UnpinAt(-1)

	// The cache remains transparent.
	again, err := r.ViewAt(0, 1)
	require.NoError(t, err)
	require.Equal(t, file[0:64], again)
}

func TestPinAtAcrossIncarnations(t *testing.T) {
	// A pinned page that gets evicted and re-read creates a new incarnation:
	// UnpinAt must only affect the current one, and the old view stays valid.
	file := testsupport.GenerateTestInputFile(255, 4096)
	r, err := readatbuf.New(bytes.NewReader(file), 64, 1)
	require.NoError(t, err)

	pinned, err := r.PinAt(0, 1)
	require.NoError(t, err)

	// Evict the pinned page and re-read it (new incarnation).
	buf := make([]byte, 64)
	_, err = r.ReadAt(buf, 64)
	require.NoError(t, err)
	_, err = r.ReadAt(buf, 0)
	require.NoError(t, err)

	// The old view is still intact, and unpinning does not corrupt anything.
	r.UnpinAt(0)
	require.Equal(t, file[0:64], pinned)

	fresh, err := r.ViewAt(0, 1)
	require.NoError(t, err)
	require.Equal(t, file[0:64], fresh)
}
