// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpf

import (
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/processmanager/ebpfapi"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// packDeltasAsPairs is the reference implementation of packing a flat delta
// list into pairs, against which the zero-copy reinterpretation is compared.
func packDeltasAsPairs(deltas []ebpfapi.StackDelta) []support.StackDeltaPair {
	pairs := make([]support.StackDeltaPair, (len(deltas)+1)/2)
	for index, delta := range deltas {
		if index%2 == 0 {
			pairs[index/2].First.AddrLow = delta.AddrLow
			pairs[index/2].First.UnwindInfo = delta.UnwindInfo
		} else {
			pairs[index/2].Second.AddrLow = delta.AddrLow
			pairs[index/2].Second.UnwindInfo = delta.UnwindInfo
		}
	}
	return pairs
}

// TestStackDeltaPairAliasing verifies that a flat delta list can be
// reinterpreted as pairs of StackDelta entries without copying, and that the
// result is identical to explicit packing.
func TestStackDeltaPairAliasing(t *testing.T) {
	deltas := []ebpfapi.StackDelta{
		{AddrLow: 0x0008, UnwindInfo: 1},
		{AddrLow: 0x0010, UnwindInfo: 2},
		{AddrLow: 0x0018, UnwindInfo: 3},
		{AddrLow: 0x0020, UnwindInfo: 4},
	}

	aliased := unsafe.Slice(
		(*support.StackDeltaPair)(unsafe.Pointer(unsafe.SliceData(deltas))), len(deltas)/2)
	packed := packDeltasAsPairs(deltas)

	require.Len(t, aliased, len(packed))
	for i := range aliased {
		assert.Equal(t, packed[i], aliased[i], "pair %d", i)
	}
}
