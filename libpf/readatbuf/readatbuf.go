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

// pinRecord tracks one outstanding PinAt view aliasing a cached page.
// The record is detached from the page on unpin or eviction: pinned views
// keep the page buffer alive, and a re-read of the same page index creates
// a new incarnation unaffected by stale handles.
type pinRecord struct {
	// pageIdx is the page index the pin was created for.
	pageIdx uint64
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

// maxPins is the fixed number of pin records. Pinning more views
// simultaneously than this fails with ErrTooManyPins.
const maxPins = 4

// ErrTooManyPins is returned by PinAt if the maximum number of
// simultaneously outstanding pinned views would be exceeded.
var ErrTooManyPins = errors.New("too many outstanding pins")

// Reader implements buffering for random access reads via the `ReaderAt` interface.
type Reader struct {
	inner    io.ReaderAt
	cache    *lru.LRU[uint64, []byte]
	pageSize uint
	stats    Statistics

	// pins tracks the outstanding PinAt views, one record per slot. A
	// pageIdx of ^uint(0) marks an unused slot. The generation counters
	// detect stale handles.
	pins [maxPins]pinRecord
}

func hashUint64(v uint64) uint32 {
	return uint32(hash.Uint64(v))
}

// New creates a new buffered reader supporting random access. The pageSize argument decides the
// size of each region (page) tracked in the cache. cacheSize defines the maximum number of pages
// to cache.
func New(inner io.ReaderAt, pageSize, cacheSize uint) (*Reader, error) {
	if pageSize == 0 {
		return nil, errors.New("pageSize cannot be zero")
	}
	if cacheSize == 0 {
		return nil, errors.New("cacheSize cannot be zero")
	}

	cache, err := lru.New[uint64, []byte](uint32(cacheSize), hashUint64)
	if err != nil {
		return nil, fmt.Errorf("failed to create internal cache: %w", err)
	}

	reader := &Reader{
		inner:    inner,
		cache:    cache,
		pageSize: pageSize,
	}

	// Mark all pin slots unused. The zero pageIdx would be a valid index.
	for i := range reader.pins {
		reader.pins[i].pageIdx = ^uint64(0)
	}

	reader.cache.SetOnEvict(func(pageIdx uint64, data []byte) {
		reader.stats.Evictions++
		pinned := false
		for i := range reader.pins {
			if reader.pins[i].pageIdx == pageIdx {
				// The page is aliased by a pinned view: detach the
				// record (the buffer is dropped to the GC, keeping
				// the outstanding view valid) and mark the slot unused.
				pinned = true
				reader.pins[i].pageIdx = ^uint64(0)
				reader.pins[i].gen++
			}
		}
		if pinned {
			return
		}
		libpf.PutBuffer(data)
	})

	return reader, nil
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

// getOrReadPage returns the data of the page pageIdx, serving it from the cache when possible.
func (reader *Reader) getOrReadPage(pageIdx uint64) ([]byte, error) {
	if cachedData, exists := reader.cache.Get(pageIdx); exists {
		// Data is cached: serve from there.
		reader.stats.Hits++
		return cachedData, nil
	}

	reader.stats.Misses++

	buffer := libpf.GetBuffer(int(reader.pageSize))

	// Read from the underlying reader. We speculatively read more than the original caller
	// asked us to, so running into EOF is expected for us and reported via the length of
	// the returned data.
	n, err := reader.inner.ReadAt(buffer, int64(pageIdx*uint64(reader.pageSize)))
	if err != nil && err != io.EOF {
		libpf.PutBuffer(buffer)
		return nil, err
	}
	if n == 0 {
		libpf.PutBuffer(buffer)
		return nil, io.EOF
	}

	buffer = buffer[:n]
	reader.cache.Add(pageIdx, buffer)
	return buffer, nil
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

	pageIdx := uint64(off) / uint64(reader.pageSize)
	pageOffset := int(uint64(off) % uint64(reader.pageSize))

	for pos := 0; pos < len(p); {
		data, err := reader.getOrReadPage(pageIdx)
		if err != nil {
			return pos, err
		}
		if pageOffset >= len(data) {
			return pos, io.EOF
		}

		copyLen := min(len(p)-pos, len(data)-pageOffset)
		copy(p[pos:][:copyLen], data[pageOffset:][:copyLen])

		pageOffset = 0
		pageIdx++
		pos += copyLen

		if pos < len(p) && uint(len(data)) < reader.pageSize {
			// The read is incomplete.
			return pos, io.EOF
		}
	}

	return len(p), nil
}

func (reader *Reader) view(offs int64, minLen int) ([]byte, error) {
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

	pageIdx := uint64(offs) / uint64(reader.pageSize)
	data, err := reader.getOrReadPage(pageIdx)
	if err != nil {
		return nil, err
	}
	if skip+uint(minLen) > uint(len(data)) {
		return nil, io.EOF
	}

	// The previous transient view is contractually invalid from now on.
	// Eviction of this page can only be triggered by a subsequent API call
	// (ReadAt, ViewAt or PinAt), which invalidates the view by contract, so
	// its buffer can be pooled normally on eviction.
	return data[skip:], nil
}

// ViewAt implements the libpf.ViewAtReader interface.
func (reader *Reader) ViewAt(offs int64, minLen int) ([]byte, error) {
	return reader.view(offs, minLen)
}

// addPin registers a pin on a cached page and returns its handle. It fails
// with ErrTooManyPins if all pin record slots are in use.
func (reader *Reader) addPin(pageIdx uint64) (libpf.PinHandle, error) {
	for slot := range reader.pins {
		if reader.pins[slot].pageIdx != ^uint64(0) {
			continue
		}
		gen := reader.pins[slot].gen + 1
		reader.pins[slot] = pinRecord{pageIdx: pageIdx, gen: gen}
		return libpf.PinHandle(uint64(gen)<<32 | uint64(uint32(slot))), nil
	}
	return 0, ErrTooManyPins
}

// PinAt returns a view like ViewAt, but pins the backing page: the view
// stays valid, and the page will not be pooled on eviction, until Unpin is
// called with the returned handle. Every returned handle must be released
// exactly once with Unpin. A page that is evicted while pinned is dropped
// to the GC, and a later re-read of the same page index creates a new
// incarnation: Unpin of a stale handle does not affect it.
// ErrTooManyPins is returned if maxPins views are already pinned.
func (reader *Reader) PinAt(offs int64, minLen int) ([]byte, libpf.PinHandle, error) {
	view, err := reader.view(offs, minLen)
	if err != nil {
		return nil, 0, err
	}
	h, err := reader.addPin(uint64(offs) / uint64(reader.pageSize))
	if err != nil {
		return nil, 0, err
	}
	return view, h, nil
}

// Unpin releases one pin, identified by a handle returned by PinAt.
// Unknown, stale or zero handles are ignored.
func (reader *Reader) Unpin(h libpf.PinHandle) {
	slot := int(uint32(h))
	gen := uint32(h >> 32)
	if slot >= maxPins || reader.pins[slot].gen != gen {
		return
	}
	// Invalidate the handle and mark the record slot unused.
	reader.pins[slot].pageIdx = ^uint64(0)
	reader.pins[slot].gen++
}
