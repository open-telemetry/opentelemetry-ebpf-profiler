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

// errNptlDBUnavailable means the nptl_db symbols are absent (glibc < 2.34, or not glibc).
var errNptlDBUnavailable = errors.New("nptl_db symbols not exported")

// glibc states its thread descriptor layout in the symbols libthread_db reads
// out of a live process (nptl_db/structs.def). They are exported under
// GLIBC_PRIVATE and glibc's build fails when one is missing from libc.dynsym,
// so they hold wherever they are present. Only glibc 2.34 and later export
// them: earlier versions kept them in libpthread's symtab, which
// distributions strip.

// dbDesc is an nptl_db field descriptor, see DB_DEFINE_DESC in
// nptl_db/thread_dbP.h.
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

// SymbolData truncates to the symbol size, so a short read means the symbol
// is too small to hold what we are asking for.
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

// glibcTPBias returns the value turning an offset within 'struct pthread'
// into an offset from the thread pointer.
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

// glibcDTVInfo derives the DTV offsets from the nptl_db symbols.
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

	// The BPF code reads the TLS block pointer at the start of the dtv array,
	// dereferenced straight from the dtv pointer with no leading header.
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

// glibcTSDInfo derives the thread specific data offsets from the nptl_db
// symbols.
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

	// Small keys are served from specific_1stblock, which structs.def does not
	// describe. It holds one second level block and precedes .specific.
	firstBlockSize := uint64(level2.nelem) * uint64(keyDataSize)
	if firstBlockSize > uint64(specific.offset) {
		return TSDInfo{}, fmt.Errorf("%d bytes of key data do not fit before .specific at %d",
			firstBlockSize, specific.offset)
	}
	offset := int64(specific.offset) - int64(firstBlockSize) + int64(keyData.offset) + bias
	if offset < math.MinInt16 || offset > math.MaxInt16 {
		return TSDInfo{}, fmt.Errorf("TSD offset %d out of range", offset)
	}

	return TSDInfo{
		Offset:     int16(offset),
		Multiplier: uint8(keyDataSize),
	}, nil
}
