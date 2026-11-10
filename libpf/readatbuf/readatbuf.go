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

// Statistics contains statistics about cache efficiency.
type Statistics struct {
	Hits      uint64
	Misses    uint64
	Evictions uint64
}

// Reader implements buffering for random access reads via the `ReaderAt` interface.
type Reader struct {
	inner    io.ReaderAt
	cache    *lru.LRU[uint64, []byte]
	pageSize uint
	stats    Statistics
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

	r := &Reader{inner: inner, cache: cache, pageSize: pageSize}
	cache.SetOnEvict(func(_ uint64, data []byte) {
		r.stats.Evictions++
		libpf.PutBuffer(data)
	})

	return r, nil
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
