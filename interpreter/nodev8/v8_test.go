// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package nodev8 // import "go.opentelemetry.io/ebpf-profiler/interpreter/nodev8"

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/elastic/go-freelru"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestRegexs(t *testing.T) {
	shouldMatch := []string{
		"node",
		"node8",
		"./node",
		"/foo/bar/node",
		"./foo/bar/node",
		"nsolid",
		"nsolid8",
		"./nsolid",
		"/foo/bar/nsolid",
		"./foo/bar/nsolid",
		"./libnode.so",
		"/lib/libnode.so.12",
	}
	for _, s := range shouldMatch {
		assert.True(t, v8Regex.MatchString(s), "regex %s should match %s",
			v8Regex.String(), s)
	}

	shouldNotMatch := []string{
		"node-foo",
		"./nsolid-bar",
		"/lib/libnodetest.so",
		"/lib/libnode.so.1.2.3.4.5",
		"node-nsolid",
	}
	for _, s := range shouldNotMatch {
		assert.False(t, v8Regex.MatchString(s), "regex %s should not match %s",
			v8Regex.String(), s)
	}
}

func newTestV8Instance() *v8Instance {
	d := &v8Data{}
	vms := &d.vmStructs
	vms.Fixed.StringRepresentationMask = 0x0f
	vms.Fixed.StringEncodingMask = 0xf0
	vms.Fixed.SeqStringTag = 0x00
	vms.Fixed.ConsStringTag = 0x01
	vms.Fixed.ThinStringTag = 0x02
	vms.Fixed.OneByteStringTag = 0x20
	vms.Fixed.FirstNonstringType = 0xf0
	vms.String.Length = 4
	vms.SeqOneByteString.Chars = 8
	vms.ConsString.First = 8
	vms.ConsString.Second = 16
	vms.ThinString.Actual = 24
	vms.HeapObject.Map = 0
	vms.Map.InstanceType = 4
	vms.FixedArrayBase.Length = 8

	addrToType, err := freelru.New[libpf.Address, uint16](64, libpf.Address.Hash32)
	if err != nil {
		panic(err)
	}
	return &v8Instance{d: d, addrToType: addrToType}
}

func putUint64(buf []byte, off int, v uint64) {
	binary.LittleEndian.PutUint64(buf[off:off+8], v)
}

func putUint16(buf []byte, off int, v uint16) {
	binary.LittleEndian.PutUint16(buf[off:off+2], v)
}

func TestExtractStringLengthLimit(t *testing.T) {
	i := newTestV8Instance()
	buf := make([]byte, 4096)
	// Advertise a ~4 GiB sequence string; extraction must fail without reading
	// or invoking the callback even once.
	binary.LittleEndian.PutUint32(buf[4:], 0xFFFFFFFF)
	i.rm = remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	tag := uint16(i.d.vmStructs.Fixed.SeqStringTag | i.d.vmStructs.Fixed.OneByteStringTag)
	calls := 0
	_, err := i.extractString(0, tag, func(string) error { calls++; return nil },
		maxMemoizedStringBytes, maxStringDepth)
	require.Error(t, err)
	require.Zero(t, calls)
}

func TestExtractStringValid(t *testing.T) {
	i := newTestV8Instance()
	buf := make([]byte, 4096)
	binary.LittleEndian.PutUint32(buf[4:], 6)
	copy(buf[8:], "abcdef")
	i.rm = remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	tag := uint16(i.d.vmStructs.Fixed.SeqStringTag | i.d.vmStructs.Fixed.OneByteStringTag)
	got := ""
	_, err := i.extractString(0, tag, func(s string) error { got += s; return nil },
		maxMemoizedStringBytes, maxStringDepth)
	require.NoError(t, err)
	assert.Equal(t, "abcdef", got)
}

func TestExtractStringConsCycle(t *testing.T) {
	i := newTestV8Instance()
	const (
		A libpf.Address = 0x1000
		M libpf.Address = 0x2000
	)
	buf := make([]byte, 0x3000)
	putUint64(buf, int(A)+int(i.d.vmStructs.HeapObject.Map), uint64(M|HeapObjectTag))
	putUint16(buf, int(M)+int(i.d.vmStructs.Map.InstanceType),
		uint16(i.d.vmStructs.Fixed.ConsStringTag))
	putUint64(buf, int(A)+int(i.d.vmStructs.ConsString.First), uint64(A|HeapObjectTag))
	putUint64(buf, int(A)+int(i.d.vmStructs.ConsString.Second), uint64(A|HeapObjectTag))
	i.rm = remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	// A self-referencing ConsString must be stopped by the depth bound instead
	// of exhausting the stack.
	_, err := i.extractString(A|HeapObjectTag, 0, func(string) error { return nil },
		maxSourceStringBytes, maxStringDepth)
	require.Error(t, err)
}

func TestReadFixedTableSizeLimit(t *testing.T) {
	i := newTestV8Instance()
	buf := make([]byte, 256)
	// A huge SMI length whose product with itemSize would wrap a uint32.
	numItems := uint64(1) << 30
	binary.LittleEndian.PutUint64(buf[8:], numItems<<32)
	i.rm = remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	_, err := i.readFixedTable(0, 8, 0)
	require.Error(t, err)
}
