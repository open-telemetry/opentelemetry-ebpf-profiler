/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package freelru is a wrapper around go-freelru.LRU with additional statistics embedded and can
// be used as a drop in replacement.
package freelru

import (
	"sync/atomic"

	lru "github.com/elastic/go-freelru"
)

// LRU is a wrapper around go-freelru.LRU with additional statistics embedded.
type LRU[K comparable, V any] struct {
	lru lru.LRU[K, V]

	// Internal statistics
	hit     atomic.Uint64
	miss    atomic.Uint64
	added   atomic.Uint64
	deleted atomic.Uint64
}

type Statistics struct {
	// Number of times for a hit of a cache entry.
	Hit uint64
	// Number of times for a miss of a cache entry.
	Miss uint64
	// Number of elements that were added to the cache.
	Added uint64
	// Number of elements that were deleted from the cache.
	Deleted uint64
}

func New[K comparable, V any](capacity uint32, hash lru.HashKeyCallback[K]) (*LRU[K, V], error) {
	cache, err := lru.New[K, V](capacity, hash)
	if err != nil {
		return nil, err
	}
	return &LRU[K, V]{
		lru: *cache,
	}, nil
}

func (c *LRU[K, V]) Add(key K, value V) (evicted bool) {
	evicted = c.lru.Add(key, value)
	if evicted {
		c.deleted.Add(1)
	}
	c.added.Add(1)
	return evicted
}

func (c *LRU[K, V]) Contains(key K) (ok bool) {
	return c.lru.Contains(key)
}

func (c *LRU[K, V]) Get(key K) (value V, ok bool) {
	value, ok = c.lru.Get(key)
	if ok {
		c.hit.Add(1)
	} else {
		c.miss.Add(1)
	}
	return value, ok
}

func (c *LRU[K, V]) Purge() {
	size := c.lru.Len()
	c.deleted.Add(uint64(size))
	c.lru.Purge()
}

func (c *LRU[K, V]) Remove(key K) (present bool) {
	present = c.lru.Remove(key)
	if present {
		c.deleted.Add(1)
	}
	return present
}

// GetAndResetStatistics returns the internal statistics for this LRU and resets all values to 0.
func (c *LRU[K, V]) GetAndResetStatistics() Statistics {
	return Statistics{
		Hit:     c.hit.Swap(0),
		Miss:    c.miss.Swap(0),
		Added:   c.added.Swap(0),
		Deleted: c.deleted.Swap(0),
	}
}
