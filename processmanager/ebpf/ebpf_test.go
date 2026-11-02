// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"fmt"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestMapID(t *testing.T) {
	testCases := map[uint32]uint16{
		0:       8,
		1:       8,
		2:       8,
		0xFF:    8,  // 255
		0x100:   9,  // 256
		0x1FF:   9,  // 511
		0x200:   10, // 512
		0x3FF:   10, // 1023
		0x400:   11, // 1024
		0xFFFFF: 20, // 1048575 (2^20 - 1)
		(1 << support.StackDeltaBucketLargest) - 1: support.StackDeltaBucketLargest,
	}
	for numStackDeltas, expectedShift := range testCases {
		t.Run(fmt.Sprintf("deltas %d", numStackDeltas), func(t *testing.T) {
			shift, err := getMapID(numStackDeltas)
			require.NoError(t, err)
			assert.Equal(t, expectedShift, shift, "wrong map name for %d deltas",
				numStackDeltas)
		})
	}

	_, err := getMapID(1 << (support.StackDeltaBucketLargest + 1))
	require.Error(t, err)
}

// TestStackDeltaFPRangeKey pins the StackDeltaFPRange key layout against the prefix lengths
// getStackDeltaFPRange builds. The kernel's LPM trie matches every byte after prefixLen as
// one big endian bit string, so the implicit hole the fileID alignment would leave becomes
// its most significant bits, where it would have every prefix match an unrelated page.
func TestStackDeltaFPRangeKey(t *testing.T) {
	var key support.StackDeltaFPRange

	// The key data starts right after prefixLen, which has to account for all of it.
	keySize := unsafe.Sizeof(key)
	require.Equal(t, uintptr(4), unsafe.Offsetof(key.Pad))
	require.Equal(t, uintptr(8), unsafe.Offsetof(key.FileID))
	require.Equal(t, uintptr(16), unsafe.Offsetof(key.Page))
	assert.Equal(t, 8*(keySize-unsafe.Sizeof(key.PrefixLen)),
		uintptr(support.BitWidthFPRangePad+support.BitWidthFileID+
			support.BitWidthStackDeltaPage),
		"prefix widths must cover the whole key data, hole included")

	// A fully specified prefix must match the entire key data, which is the max_prefixlen
	// the kernel derives from the key size.
	full := getStackDeltaFPRange(host.FileID(0x1122334455667788), lpm.Prefix{
		Key:    0x42,
		Length: support.BitWidthStackDeltaPage,
	})
	assert.Equal(t, uint32(8*(keySize-unsafe.Sizeof(key.PrefixLen))), full.PrefixLen)
	assert.Zero(t, full.Pad)

	// Shortening the prefix has to eat into the page, never into the fileID, so that a
	// range never reaches an executable that merely shares its high fileID bits.
	long := getStackDeltaFPRange(host.FileID(0xaabb), lpm.Prefix{Key: 8, Length: 64})
	short := getStackDeltaFPRange(host.FileID(0xaabb), lpm.Prefix{Key: 8, Length: 61})
	assert.Equal(t, long.FileID, short.FileID)
	assert.Equal(t, long.PrefixLen-3, short.PrefixLen)
	assert.GreaterOrEqual(t, short.PrefixLen,
		uint32(support.BitWidthFPRangePad+support.BitWidthFileID))
}
