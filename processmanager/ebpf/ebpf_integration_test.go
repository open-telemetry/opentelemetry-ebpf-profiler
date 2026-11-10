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
		ValueSize:  uint32(unsafe.Sizeof(support.StackDelta{})),
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

	// Four deltas on pages 1-4 (each slice padded to a pair boundary with a
	// duplicate of its delta), with a delta-free page 5 whose search slice
	// resolves to the covering delta of page 4.
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
	}
	pageDescs := []ebpfapi.StackDeltaPageDesc{
		// FirstPair is the pair index relative to the start of the stack
		// delta region, which holds the pairs before the page descriptors.
		{FirstPair: 0, NumPairs: 1},
		{FirstPair: 1, NumPairs: 1},
		{FirstPair: 2, NumPairs: 1},
		{FirstPair: 3, NumPairs: 1},
		{FirstPair: 4, NumPairs: 0},
	}

	fileID := host.FileID(0x1234)
	mapID, err := impl.UpdateExeIDToStackDeltas(fileID, deltas, pageDescs, firstPage)
	require.NoError(t, err)
	require.Equal(t, support.StackDeltaBucketSmallest, mapID)

	var meta support.StackDeltaMeta
	metaKey := uint64(fileID)
	require.NoError(t, metaMap.Lookup(unsafe.Pointer(&metaKey), unsafe.Pointer(&meta)))
	assert.Equal(t, uint64(firstPage), meta.FirstPage)
	assert.Equal(t, uint32(len(pageDescs)), meta.NumPages)
	assert.Equal(t, uint32(len(deltas)/2), meta.NumPairs)
	assert.Equal(t, mapID, meta.MapID)

	var innerID cebpf.MapID
	require.NoError(t, outerMap.Lookup(unsafe.Pointer(&metaKey), &innerID))
	innerMap, err := cebpf.NewMapFromID(innerID)
	require.NoError(t, err)
	defer innerMap.Close()

	for index := 0; index < len(deltas); index += 2 {
		var got support.StackDeltaPair
		key := uint32(index / 2)
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
		key := uint32(len(deltas)/2 + index)
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
