// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// readatbuf providers wrappers adding caching to types that implement the `ReaderAt` interface.

package readatbuf // import "go.opentelemetry.io/ebpf-profiler/libpf/readatbuf"

import (
	"errors"
	"fmt"
	"io"

	lru "github.com/elastic/go-freelru"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/hash"
)

// page represents a cached region from the underlying reader.
type page struct {
	// data contains the data cached from a previous read.
	data []byte
	// eof determines whether we encountered an EOF when reading the page originally.
	eof bool
	// pins is the number of outstanding PinAt views aliasing this page.
	// Pages with pins are dropped to the GC on eviction instead of being
	// pooled, keeping the outstanding views valid.
	pins int
}

// Statistics contains statistics about cache efficiency.
type Statistics struct {
	Hits      uint64
	Misses    uint64
	Evictions uint64
}

// Reader implements buffering for random access reads via the `ReaderAt` interface.
type Reader struct {
	inner    io.ReaderAt
	cache    *lru.LRU[uint, page]
	pageSize uint
	stats    Statistics

	// viewPage is the page index of the most recently handed out view, or
	// ^uint(0) if no view is outstanding. Evicting this page must not
	// return its buffer to the pool, as an outstanding view may still
	// alias it.
	viewPage uint
}

func HashUInt(v uint) uint32 {
	return uint32(hash.Uint64(uint64(v)))
}

// New creates a new buffered reader supporting random access. The pageSize argument decides the
// size of each region (page) tracked in the cache. cacheSize defines the maximum number of pages
// to cache.
func New(inner io.ReaderAt, pageSize, cacheSize uint) (reader *Reader, err error) {
	if pageSize == 0 {
		return nil, errors.New("pageSize cannot be zero")
	}
	if cacheSize == 0 {
		return nil, errors.New("cacheSize cannot be zero")
	}

	reader = &Reader{
		inner:    inner,
		pageSize: pageSize,
		viewPage: ^uint(0),
	}

	reader.cache, err = lru.New[uint, page](uint32(cacheSize), HashUInt)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal cache: %w", err)
	}

	reader.cache.SetOnEvict(func(pageIdx uint, page page) {
		reader.stats.Evictions++
		if page.pins > 0 || reader.viewPage == pageIdx {
			// The page is aliased by an outstanding view: forget the pin
			// and drop the buffer to the GC instead of pooling it.
			reader.viewPage = ^uint(0)
			page.data = nil
			return
		}
		libpf.PutBuffer(page.data)
		page.data = nil
	})

	return
}

// InvalidateCache flushes the internal cache. Resets the statistics.
func (reader *Reader) InvalidateCache() {
	reader.cache.Purge()
	reader.stats = Statistics{}
}

// Statistics returns statistics about cache efficiency.
func (reader *Reader) Statistics() Statistics {
	return reader.stats
}

// ReadAt implements the `ReaderAt` interface.
func (reader *Reader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("negative offset value %d given", off)
	}

	// If reading large amounts of data, skip the cache and use inner ReadAt
	// directly. This avoids a single read to trash the whole cache.
	// When using underlying os.File this also reduces the number of syscalls
	// made as the caching logic would split this to ReadAt call per page.
	if uint(len(p)) > reader.pageSize*3/2 {
		return reader.inner.ReadAt(p, off)
	}

	writeOffset := uint(0)
	remaining := uint(len(p))
	skipOffset := uint(off) % reader.pageSize
	pageIdx := uint(off) / reader.pageSize

	for remaining > 0 {
		data, eof, err := reader.getOrReadPage(pageIdx)
		if err != nil {
			return int(writeOffset), err
		}
		if skipOffset > uint(len(data)) {
			return 0, io.EOF
		}

		copyLen := min(remaining, uint(len(data))-skipOffset)
		copy(p[writeOffset:][:copyLen], data[skipOffset:][:copyLen])

		skipOffset = 0
		pageIdx++
		writeOffset += copyLen
		remaining -= copyLen

		if eof {
			if remaining == 0 {
				// While there was an EOF in the chunk read, the user buffer was small enough to
				// not have caused it.
				break
			}

			// The read is incomplete.
			return int(writeOffset), io.EOF
		}
	}

	return int(writeOffset), nil
}

// ViewAt implements the libpf.ViewAtReader interface.
func (reader *Reader) ViewAt(offs, minLen int64) ([]byte, error) {
	return reader.view(offs, minLen, false)
}

func (reader *Reader) view(offs, minLen int64, pin bool) ([]byte, error) {
	if offs < 0 {
		return nil, fmt.Errorf("negative offset value %d given", offs)
	}
	if minLen <= 0 {
		minLen = 1
	}

	// Fail without any I/O if the range would straddle a page boundary, so
	// that the cache does not get polluted by unsatisfiable requests.
	skip := uint(offs) % reader.pageSize
	if skip+uint(minLen) > reader.pageSize {
		return nil, libpf.ErrNotContiguous
	}

	pageIdx := uint(offs) / reader.pageSize
	data, eof, err := reader.getOrReadPage(pageIdx)
	if err != nil {
		return nil, err
	}
	if eof && skip+uint(minLen) > uint(len(data)) {
		return nil, io.EOF
	}

	// The previous transient view is contractually invalid from now on; pin
	// the page backing the new view so that its buffer is not pooled on
	// eviction.
	reader.viewPage = pageIdx
	if pin {
		reader.addPin(pageIdx)
	}
	return data[skip:], nil
}

// PinAt returns a view like ViewAt, but explicitly pins the backing page:
// the view stays valid, and the page will not be pooled on eviction, until
// UnpinAt is called with an offset within the same page. Multiple pins on
// one page are reference counted. A page that is evicted while pinned is
// dropped to the GC, and a later re-read of the same page index creates a
// new incarnation: UnpinAt only affects the current one.
func (reader *Reader) PinAt(offs, minLen int64) ([]byte, error) {
	return reader.view(offs, minLen, true)
}

// UnpinAt removes one pin from the page containing offs, added by PinAt.
// It is a no-op if the page is not cached or carries no pins.
func (reader *Reader) UnpinAt(offs int64) {
	if offs < 0 {
		return
	}
	pageIdx := uint(offs) / reader.pageSize
	if p, ok := reader.cache.Get(pageIdx); ok && p.pins > 0 {
		p.pins--
		reader.cache.Add(pageIdx, p)
	}
}

// addPin increments the pin count of a cached page.
func (reader *Reader) addPin(pageIdx uint) {
	if p, ok := reader.cache.Get(pageIdx); ok {
		p.pins++
		reader.cache.Add(pageIdx, p)
	}
}

func (reader *Reader) getOrReadPage(pageIdx uint) (data []byte, eof bool, err error) {
	if cachedPage, exists := reader.cache.Get(pageIdx); exists {
		// Data is cached: serve from there.
		reader.stats.Hits++
		return cachedPage.data, cachedPage.eof, nil
	}

	reader.stats.Misses++

	buffer := libpf.GetBuffer(int(reader.pageSize))

	// Read from the underlying reader.
	n, err := reader.inner.ReadAt(buffer, int64(pageIdx*reader.pageSize))
	if err != nil {
		// We speculatively read more than the original caller asked us to, so running into
		// EOF is actually expected for us.
		if err == io.EOF {
			buffer = buffer[:n]
			eof = true
		} else {
			libpf.PutBuffer(buffer)
			return nil, false, err
		}
	}

	if !eof && uint(n) < reader.pageSize {
		libpf.PutBuffer(buffer)
		return nil, false, errors.New("failed to read whole page")
	}

	reader.cache.Add(pageIdx, page{data: buffer, eof: eof})
	return buffer, eof, nil
}
