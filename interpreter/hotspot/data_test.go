// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package hotspot

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestParseIntrospectionStrideLimit(t *testing.T) {
	buf := make([]byte, 4096)
	// The stride value is read from target memory; place a huge one there.
	binary.LittleEndian.PutUint64(buf[0x100:], 1<<20)
	binary.LittleEndian.PutUint64(buf[8:], 1)
	rm := remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	it := &hotspotIntrospectionTable{
		base:        8,
		stride:      0x100,
		typeOffset:  0,
		fieldOffset: 8,
		valueOffset: 16,
	}
	vmd := &hotspotVMData{}
	err := vmd.parseIntrospection(it, rm, 0)
	require.Error(t, err)
}

func TestParseIntrospectionEntryLimit(t *testing.T) {
	// Fill the whole table with non-null type-name pointers so the loop cannot
	// terminate on the empty-name sentinel. The loop must still terminate at
	// the entry-count cap instead of spinning forever.
	const entries = 1 << 17
	const stride = 16
	buf := make([]byte, entries*stride)
	for i := range buf {
		buf[i] = 0x01
	}
	binary.LittleEndian.PutUint64(buf[0x100:], stride)
	binary.LittleEndian.PutUint64(buf[8:], 1)
	rm := remotememory.RemoteMemory{ReaderAt: bytes.NewReader(buf)}

	it := &hotspotIntrospectionTable{
		base:        8,
		stride:      0x100,
		typeOffset:  0,
		fieldOffset: 8,
		valueOffset: 16,
	}
	vmd := &hotspotVMData{}
	err := vmd.parseIntrospection(it, rm, 0)
	require.NoError(t, err)
}

func TestValidateVMStructSizes(t *testing.T) {
	// A fully zero vmStructs is valid.
	vmd := &hotspotVMData{}
	require.NoError(t, vmd.validateVMStructSizes())

	// Oversized class size must be rejected.
	vmd = &hotspotVMData{}
	vmd.vmStructs.ConstMethod.Sizeof = 1 << 20
	require.Error(t, vmd.validateVMStructSizes())

	// Field offset beyond the class size must be rejected.
	vmd = &hotspotVMData{}
	vmd.vmStructs.ConstMethod.Sizeof = 100
	vmd.vmStructs.ConstMethod.Flags = 200
	require.Error(t, vmd.validateVMStructSizes())

	// Oversized Symbol.Sizeof must be rejected.
	vmd = &hotspotVMData{}
	vmd.vmStructs.Symbol.Sizeof = 64
	require.Error(t, vmd.validateVMStructSizes())
}
