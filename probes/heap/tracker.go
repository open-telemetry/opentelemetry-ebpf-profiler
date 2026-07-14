// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package liveheap tracks live (in-use) heap allocations by correlating
// sampled alloc and free events. It produces periodic snapshots of the
// current live set, aggregated by allocation call stack.
package heap // import "go.opentelemetry.io/ebpf-profiler/liveheap"

import (
	"sync"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/metrics"
)

// ProcessMeta holds process metadata needed for inuse profile resource attributes.
type ProcessMeta struct {
	ExecutablePath libpf.String
	ContainerID    libpf.String
}

// allocKey uniquely identifies a live allocation: the process and the
// pointer returned to the application.
type allocKey struct {
	PID libpf.PID
	Ptr uint64
}

// allocEntry stores the metadata for one live allocation needed to
// produce inuse profiles and correlate with free events.
type allocEntry struct {
	TraceHash libpf.TraceHash
	Weight    int64
}

// InuseEntry is one row in the aggregated snapshot: a unique call stack
// and the total in-use bytes/objects attributed to it.
type InuseEntry struct {
	TraceHash libpf.TraceHash
	Frames    libpf.Frames
	PID       libpf.PID
	Space     int64 // total weight of live allocations with this stack
	Objects   int64 // count of live allocations with this stack
}

// Tracker maintains the live allocation set for all tracked processes.
// It is safe for concurrent use.
type Tracker struct {
	mu   sync.Mutex
	live map[allocKey]allocEntry

	// frames caches the resolved frame list per trace hash so that
	// snapshots can report stacks without re-symbolizing.
	frames map[libpf.TraceHash]libpf.Frames

	// liveHeapPIDs is the set of PIDs whose binary has the heap-sampler
	// free probe attached (see usdt.ProbeHeapFree). Only these PIDs get
	// tracked; without the free probe, allocs would accumulate forever.
	liveHeapPIDs map[libpf.PID]struct{}

	// Metrics
	allocSamples uint64 // alloc samples received this interval
	freeSamples  uint64 // free samples received this interval
}

// NewTracker creates a Tracker for live-heap correlation.
// Capacity is bounded by the eBPF heap_alloc_live map; the userspace
// tracker accepts all entries that eBPF committed (ptr != 0).
func NewTracker() *Tracker {
	return &Tracker{
		live:         make(map[allocKey]allocEntry, 4096),
		frames:       make(map[libpf.TraceHash]libpf.Frames, 1024),
		liveHeapPIDs: make(map[libpf.PID]struct{}),
	}
}

// SetPIDLiveHeapSupport marks whether a PID supports live heap tracking
// (i.e., has the heap-sampler free probe attached). Only PIDs with support
// enabled will have their allocations tracked.
//
// Future improvement: PIDs that have the free probe but never actually free
// memory after some observation window could be auto-demoted to save tracker
// memory. This is not implemented yet but would be useful when live heap
// profiling is dynamically configured on the application side.
func (t *Tracker) SetPIDLiveHeapSupport(pid libpf.PID, supported bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if supported {
		t.liveHeapPIDs[pid] = struct{}{}
	} else {
		delete(t.liveHeapPIDs, pid)
	}
}

// HandleAlloc records a sampled allocation. traceHash and frames come from
// the symbolized trace; ptr and weight from the eBPF event.
// Called for every received alloc sample so allocSamples is a true received
// count; a no-op beyond that count when eBPF did not live-track the alloc
// (ptr == 0) or the PID doesn't support live heap.
func (t *Tracker) HandleAlloc(pid libpf.PID, ptr uint64, traceHash libpf.TraceHash, weight int64, frames libpf.Frames) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.allocSamples++

	// eBPF zeroes ptr for allocs it did not live-track (dropped at the per-PID
	// limit or a full map, a non-live PID, or a first sighting). Count the
	// received sample above, but there is no live entry to add, and no free
	// will ever arrive for it.
	if ptr == 0 {
		return
	}

	if _, ok := t.liveHeapPIDs[pid]; !ok {
		return
	}

	key := allocKey{PID: pid, Ptr: ptr}
	t.live[key] = allocEntry{
		TraceHash: traceHash,
		Weight:    weight,
	}

	// Cache frames for this trace hash if not already present.
	if _, ok := t.frames[traceHash]; !ok && len(frames) > 0 {
		t.frames[traceHash] = frames
	}
}

// HandleFree removes a sampled allocation from the live set.
// Returns true if the allocation was found and removed.
func (t *Tracker) HandleFree(pid libpf.PID, ptr uint64) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.freeSamples++

	key := allocKey{PID: pid, Ptr: ptr}
	_, ok := t.live[key]
	if ok {
		delete(t.live, key)
	}
	return ok
}

// HandleProcessExit removes all live allocations for the given PID and
// clears its live-heap support flag.
// Returns the list of pointers that were removed, for eBPF map cleanup.
func (t *Tracker) HandleProcessExit(pid libpf.PID) []uint64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	delete(t.liveHeapPIDs, pid)

	var ptrs []uint64
	for key := range t.live {
		if key.PID == pid {
			ptrs = append(ptrs, key.Ptr)
			delete(t.live, key)
		}
	}

	// Purge frame cache entries no longer referenced by any live allocation.
	if len(ptrs) > 0 {
		t.pruneFrameCache()
	}

	return ptrs
}

// pruneFrameCache removes frame cache entries that are no longer
// referenced by any live allocation. Must be called with t.mu held.
func (t *Tracker) pruneFrameCache() {
	referenced := make(map[libpf.TraceHash]struct{}, len(t.frames))
	for _, entry := range t.live {
		referenced[entry.TraceHash] = struct{}{}
	}
	for hash := range t.frames {
		if _, ok := referenced[hash]; !ok {
			delete(t.frames, hash)
		}
	}
}

// pidTraceKey aggregates by both PID and trace hash so that inuse profiles
// can be emitted with correct per-process resource attributes.
type pidTraceKey struct {
	PID       libpf.PID
	TraceHash libpf.TraceHash
}

// Snapshot returns the current live set aggregated by (PID, trace hash).
// This is the data emitted as inuse_space/inuse_objects profiles.
func (t *Tracker) Snapshot() []InuseEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Aggregate by (pid, trace hash).
	agg := make(map[pidTraceKey]*InuseEntry, 256)
	for key, entry := range t.live {
		ak := pidTraceKey{PID: key.PID, TraceHash: entry.TraceHash}
		v, ok := agg[ak]
		if !ok {
			v = &InuseEntry{
				TraceHash: entry.TraceHash,
				Frames:    t.frames[entry.TraceHash],
				PID:       key.PID,
			}
			agg[ak] = v
		}
		v.Space += entry.Weight
		v.Objects++
	}

	result := make([]InuseEntry, 0, len(agg))
	for _, v := range agg {
		result = append(result, *v)
	}

	// Prune frame cache entries no longer referenced by any live allocation.
	// HandleFree only removes the live entry, not its (possibly now-orphaned)
	// TraceHash, so without periodic pruning t.frames would grow with every
	// distinct allocation stack ever seen and only shrink on process exit.
	// Snapshot runs once per report interval and already holds the lock, so
	// this bounds the cache to stacks with at least one live allocation.
	t.pruneFrameCache()

	return result
}

// LiveCount returns the current number of tracked live allocations.
func (t *Tracker) LiveCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.live)
}

// GetAndResetMetrics returns live-heap metrics and resets interval counters.
func (t *Tracker) GetAndResetMetrics() []metrics.Metric {
	t.mu.Lock()
	defer t.mu.Unlock()

	result := []metrics.Metric{
		{ID: metrics.IDLiveHeapEntries, Value: metrics.MetricValue(len(t.live))},
		{ID: metrics.IDHeapAllocSamples, Value: metrics.MetricValue(t.allocSamples)},
		{ID: metrics.IDHeapFreeSamples, Value: metrics.MetricValue(t.freeSamples)},
	}
	t.allocSamples = 0
	t.freeSamples = 0
	return result
}
