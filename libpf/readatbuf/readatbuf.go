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
}

// pinRecord tracks one outstanding PinAt view aliasing a cached page.
// The record is detached from the page on unpin or eviction: pinned views
// keep the page buffer alive, and a re-read of the same page index creates
// a new incarnation unaffected by stale handles.
type pinRecord struct {
	// pageIdx is the page index the pin was created for.
	pageIdx uint
	// gen is the slot generation. It is incremented each time the record
	// is detached (unpinned or evicted), so stale handles are detected.
	gen uint32
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

	// pins tracks the outstanding PinAt views, one record per pin. Free
	// slots are recycled; the generation counters detect stale handles.
	pins []pinRecord
	free []int
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
		pinned := reader.viewPage == pageIdx
		for i := range reader.pins {
			if reader.pins[i].pageIdx == pageIdx {
				// The page is aliased by a pinned view: detach the
				// record (the buffer is dropped to the GC, keeping
				// the outstanding view valid) and recycle the slot.
				pinned = true
				reader.pins[i].pageIdx = ^uint(0)
				reader.pins[i].gen++
				reader.free = append(reader.free, i)
			}
		}
		if pinned {
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
	return reader.view(offs, minLen)
}

func (reader *Reader) view(offs, minLen int64) ([]byte, error) {
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

	// The previous transient view is contractually invalid from now on.
	reader.viewPage = pageIdx
	return data[skip:], nil
}

// PinAt returns a view like ViewAt, but pins the backing page: the view
// stays valid, and the page will not be pooled on eviction, until Unpin is
// called with the returned handle. Every returned handle must be released
// exactly once with Unpin. A page that is evicted while pinned is dropped
// to the GC, and a later re-read of the same page index creates a new
// incarnation: Unpin of a stale handle does not affect it.
func (reader *Reader) PinAt(offs, minLen int64) ([]byte, libpf.PinHandle, error) {
	view, err := reader.view(offs, minLen)
	if err != nil {
		return nil, 0, err
	}
	pageIdx := uint(offs) / reader.pageSize
	return view, reader.addPin(pageIdx), nil
}

// Unpin releases one pin, identified by a handle returned by PinAt.
// Unknown, stale or zero handles are ignored.
func (reader *Reader) Unpin(h libpf.PinHandle) {
	slot := int(uint32(h))
	gen := uint32(h >> 32)
	if slot >= len(reader.pins) || reader.pins[slot].gen != gen {
		return
	}
	// Invalidate the handle and recycle the record slot.
	reader.pins[slot].pageIdx = ^uint(0)
	reader.pins[slot].gen++
	reader.free = append(reader.free, slot)
}

// addPin registers a pin on a cached page and returns its handle.
func (reader *Reader) addPin(pageIdx uint) libpf.PinHandle {
	var slot int
	var gen uint32 = 1
	if n := len(reader.free); n > 0 {
		slot = reader.free[n-1]
		reader.free = reader.free[:n-1]
		gen = reader.pins[slot].gen + 1
	} else {
		slot = len(reader.pins)
		reader.pins = append(reader.pins, pinRecord{})
	}
	reader.pins[slot] = pinRecord{pageIdx: pageIdx, gen: gen}
	return libpf.PinHandle(uint64(gen)<<32 | uint64(uint32(slot)))
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
