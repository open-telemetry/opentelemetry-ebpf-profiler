// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfbufio // import "go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"

import (
	"bytes"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/readatbuf"
)

func TestReader_BasicRead(t *testing.T) {
	data := []byte("0123456789abcdefghij")
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer r.Release()

	buf := make([]byte, 5)
	n, err := r.Read(buf)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, data[:5], buf)
	assert.Equal(t, int64(5), r.Tell())
}

func TestReader_SearchSlice(t *testing.T) {
	data := make([]byte, 10000)
	pattern := []byte("TARGET_DATA_HERE")
	copy(data[5000:], pattern)
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer r.Release()

	offset, err := r.SearchSlice(pattern)

	require.NoError(t, err)
	assert.Equal(t, int64(5000), offset)
	// Verify cursor is moved past the pattern
	assert.Equal(t, int64(5000+len(pattern)), r.Tell())
}

func TestReader_ReadByteAndDiscard(t *testing.T) {
	data := []byte("Hello World")
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer r.Release()

	// Read 'H'
	b, err := r.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte('H'), b)

	// Discard "ello "
	discarded, err := r.Discard(5)
	require.NoError(t, err)
	assert.Equal(t, 5, discarded)

	// Should be at 'W'
	b, err = r.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte('W'), b)
}

func TestReader_EOF(t *testing.T) {
	data := []byte("Short")
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer r.Release()

	_, err := r.Discard(5)
	require.NoError(t, err)

	_, err = r.ReadByte()
	assert.ErrorIs(t, err, io.EOF)
}

func TestReader_ReadString(t *testing.T) {
	data := []byte("part1,part2,part3")
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer r.Release()

	str, err := r.ReadString(',')
	require.NoError(t, err)
	assert.Equal(t, "part1", str)
}

func TestReadSlice_CrossBoundary(t *testing.T) {
	const bufferSize = 256
	a := bytes.Repeat([]byte("a"), bufferSize-10)
	b := bytes.Repeat([]byte("b"), 100)
	comma := []byte(",")
	data := slices.Concat(a, comma, b, comma)
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer r.Release()
	r.SetBufferSize(bufferSize)

	slice, err := r.ReadSlice(',')
	require.NoError(t, err)
	assert.Equal(t, a, slice)

	slice, err = r.ReadSlice(',')
	require.NoError(t, err)
	assert.Equal(t, b, slice)
}

func TestReader_InitFromView(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 251)
	}

	cached, err := readatbuf.New(bytes.NewReader(data), 64, 4)
	require.NoError(t, err)

	readAll := func(t *testing.T, r *Reader) []byte {
		t.Helper()
		var out []byte
		buf := make([]byte, 7) // odd size to cross buffer boundaries
		for {
			n, err := r.Read(buf)
			out = append(out, buf[:n]...)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}
		return out
	}

	t.Run("WholeAreaInOnePage", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(cached, 0, 64)
		defer r.Release()
		require.True(t, r.zeroCopy)
		require.Equal(t, data[:64], readAll(t, &r))
	})

	t.Run("UnalignedStartInOnePage", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(cached, 10, 54)
		defer r.Release()
		require.True(t, r.zeroCopy)
		require.Equal(t, data[10:64], readAll(t, &r))
	})

	t.Run("StraddlingAreaFallsBack", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(cached, 10, 55)
		defer r.Release()
		require.False(t, r.zeroCopy)
		require.Equal(t, data[10:65], readAll(t, &r))
	})

	t.Run("AreaLargerThanPageFallsBack", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(cached, 0, 200)
		defer r.Release()
		require.False(t, r.zeroCopy)
		require.Equal(t, data[:200], readAll(t, &r))
	})

	t.Run("SeekBackOnBorrowedView", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(cached, 0, 64)
		defer r.Release()
		require.True(t, r.zeroCopy)

		_, err := r.Seek(10, io.SeekStart)
		require.NoError(t, err)
		require.Equal(t, data[10:64], readAll(t, &r))
	})

	t.Run("StartEndSectionOnBorrowedView", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(cached, 0, 64)
		defer r.Release()
		require.True(t, r.zeroCopy)

		require.NoError(t, r.StartSection(20))
		require.Equal(t, int64(20), r.Remaining())
		require.Equal(t, data[:20], readAll(t, &r))
		r.EndSection()
		require.Equal(t, int64(44), r.Remaining())
		require.Equal(t, data[20:64], readAll(t, &r))
	})

	t.Run("PlainInitDropsView", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(cached, 0, 64)
		require.True(t, r.zeroCopy)

		r.Init(cached, 100, 64)
		require.False(t, r.zeroCopy)
		require.Equal(t, data[100:164], readAll(t, &r))
	})

	t.Run("ReleaseThenReuse", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(cached, 64, 64)
		require.True(t, r.zeroCopy)

		r.Release()
		require.Nil(t, r.buf)

		r.InitFromView(cached, 64, 64)
		defer r.Release()
		require.True(t, r.zeroCopy)
		require.Equal(t, data[64:128], readAll(t, &r))
	})

	t.Run("NonViewSource", func(t *testing.T) {
		r := Reader{}
		r.InitFromView(bytes.NewReader(data), 0, 64)
		defer r.Release()
		require.False(t, r.zeroCopy)
		require.Equal(t, data[:64], readAll(t, &r))
	})
}

func TestReader_InitSlideView(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 251)
	}
	cached, err := readatbuf.New(bytes.NewReader(data), 64, 4)
	require.NoError(t, err)

	readAll := func(t *testing.T, r *Reader) []byte {
		t.Helper()
		var out []byte
		buf := make([]byte, 7)
		for {
			n, err := r.Read(buf)
			out = append(out, buf[:n]...)
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
		}
		return out
	}

	t.Run("SlidingWindowOverPages", func(t *testing.T) {
		r := Reader{}
		r.InitSlideView(cached, 0, 200)
		defer r.Release()
		require.Equal(t, data[:200], readAll(t, &r))
	})

	t.Run("SeekBackWithinAndAcrossViews", func(t *testing.T) {
		r := Reader{}
		r.InitSlideView(cached, 0, 4096)
		defer r.Release()

		_, err := r.Seek(130, io.SeekStart)
		require.NoError(t, err)
		require.Equal(t, data[130:4096], readAll(t, &r))

		_, err = r.Seek(64, io.SeekStart)
		require.NoError(t, err)
		require.Equal(t, data[64:4096], readAll(t, &r))
	})

	t.Run("SearchSliceAcrossViews", func(t *testing.T) {
		r := Reader{}
		patternStart := 200
		r.InitSlideView(cached, 0, 4096)
		defer r.Release()

		offs, err := r.SearchSlice(data[patternStart : patternStart+20])
		require.NoError(t, err)
		require.Equal(t, int64(patternStart), offs)
	})

	t.Run("ReadSliceAcrossViews", func(t *testing.T) {
		r := Reader{}
		r.InitSlideView(cached, 0, 4096)
		defer r.Release()

		slice, err := r.ReadSlice(byte(42))
		require.NoError(t, err)
		require.Equal(t, data[:42], slice)
	})

	t.Run("WholeAreaBorrowStillPreferred", func(t *testing.T) {
		r := Reader{}
		r.InitSlideView(cached, 0, 64)
		defer r.Release()
		require.True(t, r.zeroCopy)
		require.True(t, r.slideView)
		require.Equal(t, data[:64], readAll(t, &r))
	})
}

func TestReader_SubReader(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 251)
	}
	cached, err := readatbuf.New(bytes.NewReader(data), 128, 4)
	require.NoError(t, err)

	readN := func(t *testing.T, r *Reader, n int) []byte {
		t.Helper()
		out := make([]byte, n)
		_, err := io.ReadFull(r, out)
		require.NoError(t, err)
		return out
	}

	t.Run("LendFromFullyLoadedParent", func(t *testing.T) {
		parent := Reader{}
		parent.InitFromView(cached, 0, 128)
		defer parent.Release()

		sub, err := parent.SubReader(32)
		require.NoError(t, err)
		defer sub.Release()
		require.True(t, sub.zeroCopy)
		require.Equal(t, int64(96), sub.Remaining())
		require.Equal(t, data[32:96], readN(t, sub, 64))

		// The parent is suspended while the sub-reader is active, and
		// stays valid after Release.
		require.Equal(t, data[0:64], readN(t, &parent, 64))
	})

	t.Run("OwnBufferFromSlidingParent", func(t *testing.T) {
		parent := Reader{}
		parent.InitSlideView(cached, 0, 4096)
		defer parent.Release()

		// Advance the parent so it is not fully loaded.
		require.Equal(t, data[0:100], readN(t, &parent, 100))

		sub, err := parent.SubReader(10)
		require.NoError(t, err)
		defer sub.Release()
		require.False(t, sub.zeroCopy)
		require.Equal(t, data[10:74], readN(t, sub, 64))
	})

	t.Run("NestedSubReader", func(t *testing.T) {
		parent := Reader{}
		parent.InitFromView(cached, 0, 128)
		defer parent.Release()

		sub, err := parent.SubReader(16)
		require.NoError(t, err)
		defer sub.Release()

		// The sub-reader's view covers [32, 128): a nested sub-reader at
		// offset 32 is fully covered and lends from it.
		subsub, err := sub.SubReader(32)
		require.NoError(t, err)
		defer subsub.Release()
		require.True(t, subsub.zeroCopy)
		require.Equal(t, data[32:96], readN(t, subsub, 64))
	})

	t.Run("OutOfRangeOffset", func(t *testing.T) {
		parent := Reader{}
		parent.InitFromView(cached, 0, 128)
		defer parent.Release()

		_, err := parent.SubReader(-1)
		require.Error(t, err)
		_, err = parent.SubReader(129)
		require.Error(t, err)
	})

	t.Run("PositionAndTell", func(t *testing.T) {
		parent := Reader{}
		parent.InitSlideView(cached, 0, 4096)
		defer parent.Release()

		sub, err := parent.SubReader(100)
		require.NoError(t, err)
		defer sub.Release()
		require.Equal(t, int64(100), sub.Tell())

		readN(t, sub, 30)
		require.Equal(t, int64(130), sub.Tell())
	})
}

func TestReader_PinnedWindowSurvivesSourceLookups(t *testing.T) {
	// The stream window is pinned: interleaved ViewAt lookups through the
	// same source (e.g. InternFromView-style strtab lookups) must not
	// invalidate it, even when they cause evictions.
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 251)
	}
	cached, err := readatbuf.New(bytes.NewReader(data), 64, 4)
	require.NoError(t, err)

	r := Reader{}
	r.InitSlideView(cached, 0, 4096)
	defer r.Release()

	readN := func(n int) []byte {
		out := make([]byte, n)
		_, err := io.ReadFull(&r, out)
		require.NoError(t, err)
		return out
	}

	// Consume part of the first window, then do lookups that evict pages.
	require.Equal(t, data[0:30], readN(30))
	lookup := make([]byte, 16)
	for page := int64(10); page < 50; page++ {
		view, err := cached.ViewAt(page*64, 1)
		require.NoError(t, err)
		copy(lookup, view[:16])
	}

	// The stream window must have stayed valid.
	require.Equal(t, data[30:94], readN(64))
}

func TestReader_InitFromViewUnpinsOnRelease(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 251)
	}
	cached, err := readatbuf.New(bytes.NewReader(data), 128, 4)
	require.NoError(t, err)

	r := Reader{}
	r.InitFromView(cached, 0, 128)
	require.True(t, r.zeroCopy)

	// While pinned, the view survives forced evictions.
	r.Release()

	// After Release the pin is gone: the cache is transparent again.
	view, err := cached.ViewAt(0, 1)
	require.NoError(t, err)
	require.Equal(t, data[:128], view)
}

func TestReader_StraddleReadAfterZeroCopySeek(t *testing.T) {
	// A read that straddles the end of a borrowed zero-copy view must
	// preserve the unconsumed bytes: the copy-out into an owned buffer
	// places them at the start, so the in-place move must not run again
	// (it would copy uninitialized pooled memory over the preserved data).
	data := make([]byte, 4096+128)
	for i := range data {
		data[i] = byte(i % 251)
	}
	cached, err := readatbuf.New(bytes.NewReader(data), 4096, 4)
	require.NoError(t, err)

	r := Reader{}
	r.InitSlideView(cached, 0, int64(len(data)))
	defer r.Release()

	readN := func(n int) []byte {
		out, err := r.ReadN(n)
		require.NoError(t, err)
		require.Len(t, out, n)
		return out
	}

	// Fill the first view and seek within it.
	require.Equal(t, data[0:16], readN(16))
	seekPos, err := r.Seek(4000, io.SeekStart)
	require.NoError(t, err)
	require.Equal(t, int64(4000), seekPos)

	// The remaining 96 bytes in the view are unconsumed when the straddle
	// read of 120 bytes triggers the copy-out path.
	require.Equal(t, data[4000:4120], readN(120))
}

func TestReader_ShortSlideViewAtPageBoundary(t *testing.T) {
	// A sliding zero-copy view never straddles pages: when the read
	// position is near a page boundary, fill() borrows a short view up to
	// the page end. Peek must keep filling to combine such a short view
	// with the data from the next page instead of failing with io.EOF.
	data := make([]byte, 16384)
	for i := range data {
		data[i] = byte(i % 251)
	}
	cached, err := readatbuf.New(bytes.NewReader(data), 4096, 4)
	require.NoError(t, err)

	r := Reader{}
	r.InitSlideView(cached, 0, int64(len(data)))
	defer r.Release()

	// The seek target sits 32 bytes before the second page boundary, so
	// the borrowed view covers only those 32 bytes and the read of 48
	// bytes has to continue into the next page.
	_, err = r.Seek(8160, io.SeekStart)
	require.NoError(t, err)
	out, err := r.ReadN(48)
	require.NoError(t, err)
	require.Equal(t, data[8160:8208], out)
}
