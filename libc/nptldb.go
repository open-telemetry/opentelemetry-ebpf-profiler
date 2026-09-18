// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libc // import "go.opentelemetry.io/ebpf-profiler/libc"

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

var errNptlDBUnavailable = errors.New("nptl_db symbols not exported")

// nptl_db/structs.def describes the layouts used by libthread_db.
// glibc 2.34+ exports these descriptors as GLIBC_PRIVATE, so they survive stripping.
// Earlier releases keep them in libpthread's static symbol table, which
// distributions strip. Those builds require the fallback paths.

// Descriptor format: DB_DEFINE_DESC in glibc's nptl_db/thread_dbP.h.
type dbDesc struct {
	// sizeBits is the field size in bits, or the element size for an array.
	sizeBits uint32
	// nelem is the element count of an array field, 1 otherwise.
	nelem  uint32
	offset uint32
}

const (
	descSize   = 12
	sizeofSize = 4
)

// SymbolData may truncate to the symbol's size without returning an error.
func readSymbolData(ef *pfelf.File, name libpf.SymbolName, size int) ([]byte, error) {
	_, data, err := ef.SymbolData(name, size)
	if err != nil {
		if errors.Is(err, libpf.ErrSymbolNotFound) {
			return nil, errNptlDBUnavailable
		}
		return nil, err
	}
	if len(data) < size {
		return nil, fmt.Errorf("%s is %d bytes", name, len(data))
	}
	return data, nil
}

// Descriptors are little endian on both supported architectures.
func readDBDesc(ef *pfelf.File, name libpf.SymbolName) (dbDesc, error) {
	data, err := readSymbolData(ef, name, descSize)
	if err != nil {
		return dbDesc{}, err
	}
	return dbDesc{
		sizeBits: binary.LittleEndian.Uint32(data[0:]),
		nelem:    binary.LittleEndian.Uint32(data[4:]),
		offset:   binary.LittleEndian.Uint32(data[8:]),
	}, nil
}

func readDBSizeof(ef *pfelf.File, name libpf.SymbolName) (uint32, error) {
	data, err := readSymbolData(ef, name, sizeofSize)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(data), nil
}

// Descriptor offsets are relative to struct pthread. Add this bias to make
// them relative to the thread pointer used by the BPF reader.
func glibcTPBias(ef *pfelf.File) (int64, error) {
	switch ef.Machine {
	case elf.EM_X86_64:
		// TLS_TCB_AT_TP: the thread pointer is the 'struct pthread' address.
		return 0, nil
	case elf.EM_AARCH64:
		// TLS_DTV_AT_TP: 'struct pthread' ends at the thread pointer.
		size, err := readDBSizeof(ef, "_thread_db_sizeof_pthread")
		if err != nil {
			return 0, err
		}
		return -int64(size), nil
	default:
		return 0, fmt.Errorf("unsupported arch %s", ef.Machine)
	}
}

func glibcDTVInfo(ef *pfelf.File) (DTVInfo, error) {
	entry, err := readDBDesc(ef, "_thread_db_dtv_dtv")
	if err != nil {
		return DTVInfo{}, err
	}
	dtvp, err := readDBDesc(ef, "_thread_db_pthread_dtvp")
	if err != nil {
		return DTVInfo{}, err
	}
	value, err := readDBDesc(ef, "_thread_db_dtv_t_pointer_val")
	if err != nil {
		return DTVInfo{}, err
	}
	bias, err := glibcTPBias(ef)
	if err != nil {
		return DTVInfo{}, err
	}

	// The BPF reader expects each entry's TLS block pointer at offset zero
	// and indexes the array directly from the DTV pointer.
	if value.offset != 0 {
		return DTVInfo{}, fmt.Errorf("dtv_t.pointer.val is at offset %d", value.offset)
	}
	if entry.offset != 0 {
		return DTVInfo{}, fmt.Errorf("dtv array is at offset %d", entry.offset)
	}
	if entry.sizeBits == 0 || entry.sizeBits%8 != 0 || entry.sizeBits > 8*math.MaxUint8 {
		return DTVInfo{}, fmt.Errorf("unexpected DTV entry size of %d bits", entry.sizeBits)
	}
	offset := int64(dtvp.offset) + bias
	if offset < math.MinInt16 || offset > math.MaxInt16 {
		return DTVInfo{}, fmt.Errorf("DTV offset %d out of range", offset)
	}

	return DTVInfo{
		Offset:     int16(offset),
		Multiplier: uint8(entry.sizeBits / 8),
	}, nil
}

func glibcTSDInfo(ef *pfelf.File) (TSDInfo, error) {
	specific, err := readDBDesc(ef, "_thread_db_pthread_specific")
	if err != nil {
		return TSDInfo{}, err
	}
	level2, err := readDBDesc(ef, "_thread_db_pthread_key_data_level2_data")
	if err != nil {
		return TSDInfo{}, err
	}
	keyData, err := readDBDesc(ef, "_thread_db_pthread_key_data_data")
	if err != nil {
		return TSDInfo{}, err
	}
	keyDataSize, err := readDBSizeof(ef, "_thread_db_sizeof_pthread_key_data")
	if err != nil {
		return TSDInfo{}, err
	}
	bias, err := glibcTPBias(ef)
	if err != nil {
		return TSDInfo{}, err
	}

	if keyDataSize == 0 || keyDataSize > math.MaxUint8 ||
		level2.sizeBits%8 != 0 || keyDataSize != level2.sizeBits/8 {
		return TSDInfo{}, fmt.Errorf("unexpected pthread_key_data size %d", keyDataSize)
	}

	// .specific's descriptor treats the whole pointer array as one field.
	// Both supported architectures use 64-bit pointers. Following specific[0]
	// also handles small keys without assuming specific_1stblock is adjacent.
	if specific.nelem != 1 || specific.sizeBits == 0 || specific.sizeBits%64 != 0 {
		return TSDInfo{}, fmt.Errorf("unexpected specific array size %d bits, count %d",
			specific.sizeBits, specific.nelem)
	}
	if level2.nelem == 0 || level2.nelem > math.MaxUint8 {
		return TSDInfo{}, fmt.Errorf("unexpected TSD block size %d", level2.nelem)
	}
	keyLimit := uint64(specific.sizeBits/64) * uint64(level2.nelem)
	if keyLimit > math.MaxUint16 {
		return TSDInfo{}, fmt.Errorf("TSD key limit %d out of range", keyLimit)
	}
	if keyData.sizeBits != 64 || keyData.nelem != 1 ||
		uint64(keyData.offset)+8 > uint64(keyDataSize) {
		return TSDInfo{}, fmt.Errorf("unexpected pthread_key_data.data descriptor: %+v", keyData)
	}
	dataOffset := uint64(level2.offset) + uint64(keyData.offset)
	if dataOffset > math.MaxUint8 {
		return TSDInfo{}, fmt.Errorf("TSD data offset %d out of range", dataOffset)
	}
	offset := int64(specific.offset) + bias
	if offset < math.MinInt16 || offset > math.MaxInt16 {
		return TSDInfo{}, fmt.Errorf("TSD offset %d out of range", offset)
	}

	return TSDInfo{
		Offset:       int16(offset),
		Multiplier:   uint8(keyDataSize),
		KeyLimit:     uint16(keyLimit),
		BlockEntries: uint8(level2.nelem),
		DataOffset:   uint8(dataOffset),
	}, nil
}
