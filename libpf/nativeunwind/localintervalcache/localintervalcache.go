/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package localintervalcache

import (
	"compress/gzip"
	"container/list"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/host"
	"github.com/elastic/otel-profiling-agent/libpf/nativeunwind"
	sdtypes "github.com/elastic/otel-profiling-agent/libpf/nativeunwind/stackdeltatypes"
)

// cacheElementExtension defines the file extension used for elements in the cache.
const cacheElementExtension = "gz"

// errElementTooLarge indicates that the element is larger than the max cache size.
var errElementTooLarge = errors.New("element too large for cache")

// cacheDirPathSuffix returns the subdirectory within `config.CacheDirectory()` that will be used
// as the data directory for the interval cache. It contains the ABI version of the cache.
func cacheDirPathSuffix() string {
	return fmt.Sprintf("otel-profiling-agent/interval_cache/%v", sdtypes.ABI)
}

// entryInfo holds the size and lru list entry for a cache element.
type entryInfo struct {
	size     uint64
	lruEntry *list.Element
}

// Cache implements the `nativeunwind.IntervalCache` interface. It stores its cache data in a local
// sub-directory of `CacheDirectory`.
// The cache evicts data based on a LRU policy, with usage order preserved across HA restarts.
// If the cache grows larger than maxSize bytes elements will be removed from the cache before
// adding new ones, starting by the element with the oldest access time. To keep the order of the
// LRU cache across restarts, the population of the LRU is based on the access time information
// of existing elements.
type Cache struct {
	hitCounter  atomic.Uint64
	missCounter atomic.Uint64

	cacheDir string
	// maxSize represents the configured maximum size of the cache.
	maxSize uint64

	// A mutex to synchronize access to internal fields entries and lru to avoid race conditions.
	mu sync.RWMutex
	// entries maps the name of elements in the cache to their size and element in the lru list.
	entries map[string]entryInfo
	// lru holds a list of elements in the cache ordered by their last access time.
	lru *list.List
}

// Compile time check that the Cache implements the IntervalCache interface
var _ nativeunwind.IntervalCache = &Cache{}

// We define 2 pools to offload the GC from allocating and freeing gzip writers and readers.
// The pools will be used to write/read files of the intervalcache during encoding/decoding.
var (
	compressors = sync.Pool{
		New: func() any {
			return gzip.NewWriter(io.Discard)
		},
	}

	decompressors = sync.Pool{
		New: func() any {
			return &gzip.Reader{}
		},
	}
)

// elementData holds the access time from the file system information and size information
// for an element.
type elementData struct {
	atime time.Time
	name  string
	size  uint64
}

// New creates a new Cache using `path.Join(config.CacheDirectory(), cacheDirPathSuffix())` as the
// data directory for the cache. If that directory does not exist it will be created. However,
// `CacheDirectory` itself must already exist.
func New(maxSize uint64) (*Cache, error) {
	cacheDir := path.Join(config.CacheDirectory(), cacheDirPathSuffix())
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cacheDir, os.ModePerm); err != nil {
			return nil, fmt.Errorf("failed to create interval cache directory (%s): %s", cacheDir,
				err)
		}
	}

	// Directory exists. Make sure we can read from and write to it.
	if err := unix.Access(cacheDir, unix.R_OK|unix.W_OK); err != nil {
		return nil, fmt.Errorf("interval cache directory (%s) exists but we can't read or write it",
			cacheDir)
	}

	// Delete cache entries from obsolete ABI versions.
	if err := deleteObsoletedABICaches(cacheDir); err != nil {
		return nil, err
	}

	var elements []elementData

	// Elements in the localintervalcache are persistent on the file system. So we add the already
	// existing elements to elements, so we can sort them based on the access time and put them
	// into the cache.
	err := filepath.WalkDir(cacheDir, func(path string, info fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			entry, errInfo := info.Info()
			if errInfo != nil {
				log.Debugf("Did not get file info from '%s': %v", path, errInfo)
				// We return nil here instead of the error to continue walking
				// entries in cacheDir.
				return nil
			}
			stat := entry.Sys().(*syscall.Stat_t)
			atime := time.Unix(stat.Atim.Sec, stat.Atim.Nsec)
			elements = append(elements, elementData{
				name:  info.Name(),
				size:  uint64(entry.Size()),
				atime: atime,
			})
		}
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get preexisting cache elements: %v", err)
	}

	// Sort all elements based on their access time from oldest to newest.
	sort.SliceStable(elements, func(i, j int) bool {
		return elements[i].atime.Before(elements[j].atime)
	})

	entries := make(map[string]entryInfo)
	lru := list.New()

	// Put the information about preexisting elements into the cache. As elements
	// is sorted based on the access time from oldest to newest we add the next element
	// before the last added element into the lru.
	for _, e := range elements {
		lruEntry := lru.PushFront(e.name)
		entries[e.name] = entryInfo{
			size:     e.size,
			lruEntry: lruEntry,
		}
	}

	return &Cache{
		maxSize:  maxSize,
		cacheDir: cacheDir,
		entries:  entries,
		lru:      lru}, nil
}

// GetCurrentCacheSize returns the current size of all elements in the cache.
func (c *Cache) GetCurrentCacheSize() (uint64, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var size uint64
	for _, entry := range c.entries {
		size += entry.size
	}
	return size, nil
}

// getCacheFile constructs the path in the cache for the interval data associated
// with the provided executable ID.
func (c *Cache) getPathForCacheFile(exeID host.FileID) string {
	return fmt.Sprintf("%s/%s.%s", c.cacheDir, exeID.StringNoQuotes(), cacheElementExtension)
}

// HasIntervals returns true if interval data exists in the cache for a file with the provided
// ID, or false otherwise.
func (c *Cache) HasIntervals(exeID host.FileID) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, ok := c.entries[exeID.StringNoQuotes()+"."+cacheElementExtension]
	if !ok {
		c.missCounter.Add(1)
		return false
	}
	c.hitCounter.Add(1)
	return true
}

func gzipWriterGet(out io.Writer) *gzip.Writer {
	w := compressors.Get().(*gzip.Writer)
	w.Reset(out)
	return w
}

func gzipWriterPut(w *gzip.Writer) error {
	if err := w.Flush(); err != nil {
		return err
	}
	compressors.Put(w)
	return nil
}

func gzipReaderGet(in io.Reader) (*gzip.Reader, error) {
	w := decompressors.Get().(*gzip.Reader)
	if err := w.Reset(in); err != nil {
		return nil, err
	}
	return w, nil
}

func gzipReaderPut(r *gzip.Reader) {
	decompressors.Put(r)
}

// decompressAndDecode provides the ability to decompress and decode data that has been written to
// a file with `compressAndEncode`. The `destination` must be passed by reference.
func (c *Cache) decompressAndDecode(inPath string, destination any) error {
	reader, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("failed to open %s: %s", inPath, err)
	}
	defer reader.Close()

	zr, err := gzipReaderGet(reader)
	if err != nil {
		return fmt.Errorf("failed to create new gzip reader on %s: %s", inPath, err)
	}
	defer gzipReaderPut(zr)

	decoder := gob.NewDecoder(zr)
	err = decoder.Decode(destination)
	if err != nil {
		return fmt.Errorf("failed to decompress and decode data from %s: %s", inPath, err)
	}

	return nil
}

// encodeAndCompress provides the ability to encode a generic data type, compress it, and write
// it to the provided output path.
func (c *Cache) encodeAndCompress(outPath string, source any) error {
	// Open a file, create it if not existent
	out, err := os.OpenFile(outPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open local interval cache file at %s: %v", outPath, err)
	}
	defer out.Close()
	zw := gzipWriterGet(out)

	// Encode and compress the data, write the data to the cache file
	encoder := gob.NewEncoder(zw)
	if err := encoder.Encode(source); err != nil {
		return fmt.Errorf("failed to encode and compress data: %s", err)
	}

	return gzipWriterPut(zw)
}

// GetIntervalData loads the interval data from the cache that is associated with `exeID`
// into `interval`.
func (c *Cache) GetIntervalData(exeID host.FileID, interval *sdtypes.IntervalData) error {
	// Load the data and check for errors before updating the IntervalStructures, to avoid
	// half-initializing it.
	var data sdtypes.IntervalData
	cacheElementPath := c.getPathForCacheFile(exeID)
	if err := c.decompressAndDecode(cacheElementPath, &data); err != nil {
		return fmt.Errorf("failed to load stack delta ranges: %s", err)
	}
	*interval = data

	c.mu.Lock()
	// Update the last access information for this element.
	entryName := filepath.Base(cacheElementPath)
	entry := c.entries[entryName]
	c.lru.MoveToFront(entry.lruEntry)
	c.mu.Unlock()

	// Update the access and modification time for the element on the file system with the
	// current time. So in case of a restart of our host agent we can order the elements in
	// the cache correctly.

	// Use non-nil argument to Utime to mitigate GO bug for ARM64 Linux
	curTime := &syscall.Timeval{}
	if err := syscall.Gettimeofday(curTime); err != nil {
		return fmt.Errorf("failed to get current time: %s", err)
	}

	fileTime := &unix.Utimbuf{
		Actime:  curTime.Sec,
		Modtime: curTime.Sec,
	}
	if err := unix.Utime(cacheElementPath, fileTime); err != nil {
		// We just log the error here instead of returning it as for further processing
		// the relevant interval data is available.
		// Not being able to update the access and modification time might indicate a
		// problem with the file system. As a result on a restart of our host agent
		// the order of elements in the cache might not be correct.
		log.Errorf("Failed to update access time for '%s': %v", cacheElementPath, err)
	}

	return nil
}

// SaveIntervalData stores the provided `interval` that is associated with `exeID`
// in the cache.
func (c *Cache) SaveIntervalData(exeID host.FileID, interval *sdtypes.IntervalData) error {
	cacheElement := c.getPathForCacheFile(exeID)
	if err := c.encodeAndCompress(cacheElement, interval); err != nil {
		return fmt.Errorf("failed to save stack delta ranges: %s", err)
	}
	info, err := os.Stat(cacheElement)
	if err != nil {
		return err
	}

	cacheElementSize := uint64(info.Size())
	if cacheElementSize > c.maxSize {
		if err = os.RemoveAll(cacheElement); err != nil {
			return fmt.Errorf("failed to delete '%s': %v", cacheElement, err)
		}
		return fmt.Errorf("too large interval data for 0x%x (%d bytes): %w",
			exeID, cacheElementSize, errElementTooLarge)
	}

	// In this implementation of the cache GetCurrentCacheSize never returns an error
	currentSize, _ := c.GetCurrentCacheSize()

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.maxSize < currentSize+cacheElementSize {
		if err = c.evictEntries(currentSize + cacheElementSize - c.maxSize); err != nil {
			return err
		}
	}

	entryName := info.Name()
	lruEntry := c.lru.PushFront(entryName)
	c.entries[info.Name()] = entryInfo{
		size:     cacheElementSize,
		lruEntry: lruEntry,
	}
	return nil
}

// GetAndResetHitMissCounters retrieves the current hit and miss counters and
// resets them to 0.
func (c *Cache) GetAndResetHitMissCounters() (hit, miss uint64) {
	hit = c.hitCounter.Swap(0)
	miss = c.missCounter.Swap(0)
	return hit, miss
}

// deleteObsoletedABICaches deletes all data that is related to obsolete ABI versions.
func deleteObsoletedABICaches(cacheDir string) error {
	cacheBase := filepath.Dir(cacheDir)

	for i := 0; i < sdtypes.ABI; i++ {
		oldABICachePath := fmt.Sprintf("%s/%d", cacheBase, i)
		if _, err := os.Stat(oldABICachePath); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if err := os.RemoveAll(oldABICachePath); err != nil {
			return err
		}
	}
	return nil
}

// evictEntries deletes elements from the cache. It will delete elements with the oldest modTime
// information until the sum of deleted bytes is at toBeDeletedBytes.
// The caller is responsible to hold the lock on the cache to avoid race conditions.
func (c *Cache) evictEntries(toBeDeletedBytes uint64) error {
	// sumDeletedBytes holds the number of bytes that are already deleted
	// from this cache.
	var sumDeletedBytes uint64

	for {
		if toBeDeletedBytes <= sumDeletedBytes {
			return nil
		}
		oldestEntry := c.lru.Back()
		if oldestEntry == nil {
			return fmt.Errorf("cache is now empty - %d bytes were requested to be deleted, "+
				"but there were only %d bytes in the cache", toBeDeletedBytes, sumDeletedBytes)
		}
		entryName := oldestEntry.Value.(string)

		// Remove element from the filesystem.
		if err := os.RemoveAll(path.Join(c.cacheDir, entryName)); err != nil {
			return fmt.Errorf("failed to delete %s: %v",
				path.Join(c.cacheDir, entryName), err)
		}

		// Remove information about the element from the cache.
		c.lru.Remove(oldestEntry)
		sumDeletedBytes += c.entries[entryName].size
		delete(c.entries, entryName)
	}
}
