//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"context"
	"errors"
	"testing"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/metrics"
	"go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func loadTracers(t *testing.T) *ebpfMapsImpl {
	t.Helper()

	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	pidPageToMappingInfo, err := cebpf.NewMap(coll.Maps["pid_page_to_mapping_info"])
	require.NoError(t, err)

	return &ebpfMapsImpl{
		PidPageToMappingInfo: pidPageToMappingInfo,
		errCounter:           make(map[metrics.MetricID]int64),
	}
}

func TestLPM(t *testing.T) {
	tests := map[string]struct {
		pid      libpf.PID
		page     uint64
		pageBits uint32
		rip      uint64
		fileID   uint64
		bias     uint64
	}{
		"direct": {pid: 1000, page: 0xAA55AA, pageBits: 64, rip: 0xAA55AA, fileID: 123, bias: 456},
		"random": {pid: 123, page: 0x500000, pageBits: 44, rip: 0x5a63b5, fileID: 456, bias: 789},
	}

	impl := loadTracers(t)

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			prefix := lpm.Prefix{
				Key:    test.page,
				Length: test.pageBits,
			}
			err := impl.UpdatePidPageMappingInfo(test.pid, prefix, test.fileID, test.bias)
			require.NoError(t, err)

			fileID, bias, err := impl.LookupPidPageInformation(test.pid, test.rip)
			if assert.NoError(t, err) {
				assert.Equal(t, test.fileID, uint64(fileID))
				assert.Equal(t, test.bias, bias)
			}

			_, err = impl.DeletePidPageMappingInfo(test.pid, []lpm.Prefix{prefix})
			require.NoError(t, err)
		})
	}
}

func TestBatchOperations(t *testing.T) {
	for _, mapType := range []cebpf.MapType{cebpf.Hash, cebpf.Array, cebpf.LPMTrie} {
		t.Run(mapType.String(), func(t *testing.T) {
			if err := probeBatchOperations(mapType); err != nil {
				require.ErrorIs(t, err, cebpf.ErrNotSupported)
			}
		})
	}
}

// TestUpdateExeIDToStackDeltas verifies that the combined stack delta update
// writes the page descriptors, the stack deltas and the routing meta entry,
// and that deletion removes the meta entry and the outer map reference.
func TestUpdateExeIDToStackDeltas(t *testing.T) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	innerTemplate := &cebpf.MapSpec{
		Type:       cebpf.Array,
		KeySize:    4,
		ValueSize:  uint32(unsafe.Sizeof(support.StackDeltaPair{})),
		MaxEntries: 1 << support.StackDeltaBucketSmallest,
	}
	outerMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.HashOfMaps,
		KeySize:    8,
		ValueSize:  4,
		MaxEntries: 16,
		InnerMap:   innerTemplate,
	})
	require.NoError(t, err)
	defer outerMap.Close()

	metaMap, err := cebpf.NewMap(&cebpf.MapSpec{
		Type:       cebpf.Hash,
		KeySize:    8,
		ValueSize:  uint32(unsafe.Sizeof(support.StackDeltaMeta{})),
		MaxEntries: 16,
	})
	require.NoError(t, err)
	defer metaMap.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	numBuckets := support.StackDeltaBucketLargest - support.StackDeltaBucketSmallest + 1
	impl := &ebpfMapsImpl{
		ExeIDToStackDeltaMaps:      make([]*cebpf.Map, numBuckets),
		ExeIDToStackDeltaMeta:      metaMap,
		stackdeltaInnerMapTemplate: innerTemplate,
		errCounter:                 make(map[metrics.MetricID]int64),
		updateWorkers:              newAsyncMapUpdaterPool(ctx, 1, 8),
	}
	impl.ExeIDToStackDeltaMaps[0] = outerMap

	// Five deltas on pages 1-5 (each slice padded to a pair boundary with a
	// duplicate of its delta, except the last one), with a delta-free page 6
	// whose search slice resolves to the covering delta of page 5. The final
	// delta is left unpaired, exercising the single-element tail update.
	const firstPage = 1
	deltas := []ebpfapi.StackDelta{
		{AddrLow: 0x0000, UnwindInfo: 10},
		{AddrLow: 0x0000, UnwindInfo: 10},
		{AddrLow: 0x0000, UnwindInfo: 11},
		{AddrLow: 0x0000, UnwindInfo: 11},
		{AddrLow: 0x0010, UnwindInfo: 12},
		{AddrLow: 0x0010, UnwindInfo: 12},
		{AddrLow: 0x0000, UnwindInfo: 13},
		{AddrLow: 0x0000, UnwindInfo: 13},
		{AddrLow: 0x0000, UnwindInfo: 14},
	}
	pageDescs := []ebpfapi.StackDeltaPageDesc{
		// FirstPair is the absolute pair index in the inner map, which holds
		// the page descriptors first, then the pairs. FallbackInfo covers
		// the addresses below the page's first own delta; for the first
		// page it is STACK_DELTA_INVALID, as there is no delta covering
		// them.
		{FirstPair: 6, NumPairs: 1, FallbackInfo: support.DeltaCommandFlag},
		{FirstPair: 7, NumPairs: 1, FallbackInfo: 10},
		{FirstPair: 8, NumPairs: 1, FallbackInfo: 11},
		{FirstPair: 9, NumPairs: 1, FallbackInfo: 12},
		{FirstPair: 10, NumPairs: 1, FallbackInfo: 13},
		{FirstPair: 11, NumPairs: 0, FallbackInfo: 14},
	}

	fileID := host.FileID(0x1234)
	mapID, err := impl.UpdateExeIDToStackDeltas(fileID, deltas, pageDescs, firstPage)
	require.NoError(t, err)
	require.Equal(t, support.StackDeltaBucketSmallest, int(mapID))

	var meta support.StackDeltaMeta
	metaKey := uint64(fileID)
	require.NoError(t, metaMap.Lookup(unsafe.Pointer(&metaKey), unsafe.Pointer(&meta)))
	assert.Equal(t, uint32(firstPage), meta.FirstPage)
	assert.Equal(t, uint32(mapID), meta.MapID)
	assert.Equal(t, uint32(len(pageDescs)), meta.NumPages)

	// The outer map entry is created asynchronously by the updater pool.
	var innerMap *cebpf.Map
	require.Eventually(t, func() bool {
		var innerID cebpf.MapID
		if err := outerMap.Lookup(unsafe.Pointer(&metaKey), &innerID); err != nil {
			return false
		}
		var err error
		innerMap, err = cebpf.NewMapFromID(innerID)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond)
	defer func() {
		if innerMap != nil {
			innerMap.Close()
		}
	}()

	for index := 0; index < len(deltas); index += 2 {
		var got support.StackDeltaPair
		key := uint32(len(pageDescs) + index/2)
		require.NoErrorf(t, innerMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&got)),
			"stack delta pair %d", index/2)
		assert.Equal(t, deltas[index].AddrLow, got.First.AddrLow, "stack delta %d", index)
		assert.Equal(t, deltas[index].UnwindInfo, got.First.UnwindInfo, "stack delta %d", index)
		if index+1 < len(deltas) {
			assert.Equal(t, deltas[index+1].AddrLow, got.Second.AddrLow, "stack delta %d", index+1)
			assert.Equal(t, deltas[index+1].UnwindInfo, got.Second.UnwindInfo, "stack delta %d", index+1)
		}
	}
	for index, want := range pageDescs {
		var got ebpfapi.StackDeltaPageDesc
		key := uint32(index)
		require.NoErrorf(t, innerMap.Lookup(unsafe.Pointer(&key), unsafe.Pointer(&got)),
			"page descriptor %d", index)
		assert.Equal(t, want, got, "page descriptor %d", index)
	}

	require.NoError(t, impl.DeleteExeIDToStackDeltas(fileID, mapID))

	// The meta entry is removed synchronously.
	err = metaMap.Delete(unsafe.Pointer(&metaKey))
	require.ErrorIs(t, err, cebpf.ErrKeyNotExist)

	// The outer map entry is removed asynchronously.
	assert.Eventually(t, func() bool {
		var id cebpf.MapID
		return errors.Is(outerMap.Lookup(unsafe.Pointer(&metaKey), &id), cebpf.ErrKeyNotExist)
	}, 5*time.Second, 10*time.Millisecond)
}
