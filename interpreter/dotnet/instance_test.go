// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"

	"github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

type fakeEbpf struct {
	interpreter.EbpfHandler
}

func (fakeEbpf) UpdatePidInterpreterMapping(libpf.PID, lpm.Prefix, uint8, host.FileID, uint64) error {
	return nil
}

type countingReaderAt struct {
	r     io.ReaderAt
	reads int
}

func (c *countingReaderAt) ReadAt(p []byte, off int64) (int, error) {
	c.reads++
	return c.r.ReadAt(p, off)
}

func putUint64(buf []byte, off int, v uint64) {
	binary.LittleEndian.PutUint64(buf[off:off+8], v)
}

func newTestDotnetInstance(rm remotememory.RemoteMemory) *dotnetInstance {
	d := &dotnetData{}
	_, err := d.GetOrInit(func() (dotnetCdac, error) {
		cdac := dotnetCdac{}
		vms := &cdac.Types
		vms.RangeSection.RangeBegin = 0
		vms.RangeSection.RangeEndOpen = 8
		vms.RangeSection.Flags = 0x10
		vms.RangeSection.next = 24
		vms.RangeSection.HeapList = 0x28
		vms.RangeSection.R2RModule = 0x20
		vms.RangeSection.RangeList = 0x30
		vms.RangeSection.SizeOf = 0x38
		vms.CodeHeapListNode.SizeOf = 0x30
		vms.CodeHeapListNode.MapBase = 0x20
		vms.CodeHeapListNode.HeaderMap = 0x28
		vms.CodeHeapListNode.Next = 0
		vms.CodeHeapListNode.StartAddress = 0x10
		vms.CodeHeapListNode.EndAddress = 0x18
		return cdac, nil
	})
	if err != nil {
		panic(err)
	}
	return &dotnetInstance{
		d:      d,
		rm:     rm,
		ranges: make(map[libpf.Address]dotnetRangeSection),
	}
}

// TestWalkRangeSectionListCycle verifies that a cyclic RangeSection.next chain
// terminates instead of looping forever.
func TestWalkRangeSectionListCycle(t *testing.T) {
	const (
		r1   libpf.Address = 0x1000
		r2   libpf.Address = 0x1040
		head libpf.Address = 0x1080
	)
	buf := make([]byte, 0x1100)
	putUint64(buf, int(head), uint64(r1))
	putUint64(buf, int(r1)+24, uint64(r2))
	putUint64(buf, int(r2)+24, uint64(r1))
	rm := remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}
	i := newTestDotnetInstance(rm)
	i.codeRangeListPtr = head

	err := i.walkRangeSectionList(fakeEbpf{}, 0)
	require.NoError(t, err)
	require.Empty(t, i.ranges)
}

// TestWalkRangeListCycle verifies that a cyclic stub RangeList block chain
// terminates instead of looping forever.
func TestWalkRangeListCycle(t *testing.T) {
	const (
		b1   libpf.Address = 0x1000
		b2   libpf.Address = 0x1200
		head libpf.Address = 0x1000 - 8
	)
	buf := make([]byte, 0x2000)
	fillRanges := func(base libpf.Address, next libpf.Address, valueStart uint64) {
		for index := 0; index < 10; index++ {
			start := valueStart + uint64(index*0x100)
			putUint64(buf, int(base)+index*24, start)
			putUint64(buf, int(base)+index*24+8, start+0x10)
			putUint64(buf, int(base)+index*24+16, uint64(index+1))
		}
		putUint64(buf, int(base)+240, uint64(next))
	}
	fillRanges(b1, b2, 0x1000)
	fillRanges(b2, b1, 0x3000) // cycle back to b1

	rm := remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}
	i := newTestDotnetInstance(rm)

	i.walkRangeList(fakeEbpf{}, 0, head, codeStubPrecode)
	// b1 processed once, b2 once, then the cycle back to b1 is detected.
	require.Len(t, i.ranges, 20)
}

// TestMarkSeen verifies that markSeen deduplicates addresses and enforces the
// maxRangeSectionWalkNodes bound on a single walk.
func TestMarkSeen(t *testing.T) {
	w := &rangeWalker{seenAddress: make(map[libpf.Address]libpf.Void)}

	for addr := libpf.Address(0); addr < maxRangeSectionWalkNodes; addr++ {
		fresh, err := w.markSeen(addr)
		require.NoError(t, err)
		require.True(t, fresh)
	}
	// A new address beyond the bound must be rejected.
	fresh, err := w.markSeen(maxRangeSectionWalkNodes)
	require.Error(t, err)
	require.False(t, fresh)
	// Already-seen addresses stay accepted (dedup, not an error).
	fresh, err = w.markSeen(0)
	require.NoError(t, err)
	require.False(t, fresh)
}

func putAllEntries(buf []byte, at, val libpf.Address) {
	for off := 0; off < 256*8; off += 8 {
		putUint64(buf, int(at)+off, uint64(val))
	}
}

// TestWalkRangeSectionMapAlias verifies that aliased intermediate level pointers
// in a RangeSectionMap are deduplicated and the whole walk is bounded.
func TestWalkRangeSectionMapAlias(t *testing.T) {
	const (
		root     libpf.Address = 0x2000
		l2       libpf.Address = 0x4000
		l3       libpf.Address = 0x6000
		l4       libpf.Address = 0x8000
		l5       libpf.Address = 0xA000
		frag     libpf.Address = 0xC000
		rangeSec libpf.Address = 0xE000
	)
	buf := make([]byte, 0x10000)
	// Every entry of every level aliases the same child, producing a full 256-way
	// fan-out that would be exponential without intermediate-level dedup.
	putAllEntries(buf, root, l2)
	putAllEntries(buf, l2, l3)
	putAllEntries(buf, l3, l4)
	putAllEntries(buf, l4, l5)
	putAllEntries(buf, l5, frag)
	putUint64(buf, int(frag)+24, uint64(rangeSec))

	cr := &countingReaderAt{r: bytes.NewReader(buf)}
	rm := remotememory.RemoteMemory{ReaderAt: cr}
	i := newTestDotnetInstance(rm)
	i.codeRangeListPtr = root

	err := i.walkRangeSectionMap(fakeEbpf{}, 0)
	require.NoError(t, err)
	// Each level is read exactly once plus a handful of fragments/sections.
	require.Less(t, cr.reads, 100)
}

func TestReadMethodDynamicName(t *testing.T) {
	const (
		methodDescPtr       = libpf.Address(0x100)
		methodNamePtr       = 0x200
		methodDescFlagsOffs = 0x6
		dynamicMethodName   = "lambda_method1"
	)

	tests := map[string]struct {
		methodNameFieldOffs uint
		wantName            string
	}{
		"friendly name": {
			methodNameFieldOffs: 0x20,
			wantName:            dynamicMethodName,
		},
		"missing cDAC field": {},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			memory := make([]byte, 0x400)
			binary.LittleEndian.PutUint16(memory[int(methodDescPtr)+methodDescFlagsOffs:], mcDynamic)
			if tt.methodNameFieldOffs != 0 {
				binary.LittleEndian.PutUint64(
					memory[int(methodDescPtr)+int(tt.methodNameFieldOffs):], methodNamePtr)
				copy(memory[methodNamePtr:], dynamicMethodName+"\x00")
			}

			cdac := dotnetCdac{}
			cdac.Types.MethodDesc.Flags = methodDescFlagsOffs
			cdac.Types.MethodDesc.SizeOf = 0x8
			cdac.Types.DynamicMethodDesc.MethodName = tt.methodNameFieldOffs

			d := &dotnetData{}
			_, err := d.GetOrInit(func() (dotnetCdac, error) {
				return cdac, nil
			})
			require.NoError(t, err)

			instance := &dotnetInstance{
				d:  d,
				rm: remotememory.RemoteMemory{ReaderAt: bytes.NewReader(memory)},
			}
			method, err := instance.readMethod(methodDescPtr, 0)
			require.NoError(t, err)
			require.NotNil(t, method)
			assert.Equal(t, uint16(mcDynamic), method.classification)
			assert.Equal(t, tt.wantName, method.dynamicName.String())
		})
	}
}

func TestSymbolizeDynamicMethod(t *testing.T) {
	const codeHeaderPtr = libpf.Address(0x1234)

	tests := map[string]struct {
		dynamicName string
		wantName    string
	}{
		"friendly name": {
			dynamicName: "lambda_method1",
			wantName:    "lambda_method1",
		},
		"missing name": {
			wantName: "[stub: dynamic]",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			addrToMethod, err := freelru.New[libpf.Address, *dotnetMethod](
				interpreter.LruFunctionCacheSize, libpf.Address.Hash32)
			require.NoError(t, err)
			addrToMethod.Add(codeHeaderPtr, &dotnetMethod{
				classification: mcDynamic,
				dynamicName:    libpf.Intern(tt.dynamicName),
			})

			instance := &dotnetInstance{addrToMethod: addrToMethod}
			ebpfFrame := libpf.NewEbpfFrame(libpf.DotnetFrame, 0, 2, 0)
			ebpfFrame[1] = uint64(codeHeaderPtr)<<5 | codeJIT

			var frames libpf.Frames
			var mapping libpf.FrameMapping
			err = instance.Symbolize(ebpfFrame, &frames, mapping)
			require.NoError(t, err)
			require.Len(t, frames, 1)
			assert.Equal(t, tt.wantName, frames[0].Value().FunctionName.String())
		})
	}
}
