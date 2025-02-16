// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package beam // import "go.opentelemetry.io/ebpf-profiler/interpreter/beam"

// Minimal JITDUMP file reader for BEAM

// This has the minimal code we need to read the JITDUMP files that the BEAM
// writes to `/tmp/jit-<pid>.dump`. It isn't BEAM-specific, so it could probably
// be used more generally. The spec for this file format is at:
// https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/tools/perf/Documentation/jitdump-specification.txt

import (
	"encoding/binary"
	"fmt"
	"io"
)

type JITDumpHeader struct {
	Magic     uint32 // the ASCII string "JiTD", written is as 0x4A695444. The reader will detect an endian mismatch when it reads 0x4454694a
	Version   uint32 // a 4-byte value representing the format version. It is currently set to 1
	TotalSize uint32 // size in bytes of file header
	ELFMach   uint32 // ELF architecture encoding (ELF e_machine value as specified in /usr/include/elf.h)
	Pad1      uint32 // padding. Reserved for future use
	Pid       uint32 // JIT runtime process identification (OS specific)
	Timestamp uint64 // timestamp of when the file was created
	Flags     uint64 // a bitmask of flags
}

type JITDumpRecordHeader struct {
	ID        uint32 // a value identifying the record type (e.g. beam.JITCodeLoad)
	TotalSize uint32 // the size in bytes of the record including this header
	Timestamp uint64 // a timestamp of when the record was created
}

const (
	JITCodeLoad          = 0 // record describing a jitted function
	JITCodeMove          = 1 // record describing an already jitted function which is moved
	JITCodeDebugInfo     = 2 // record describing the debug information for a jitted function
	JITCodeClose         = 3 // record marking the end of the jit runtime (optional)
	JITCodeUnwindingInfo = 4 // record describing a function unwinding information
)

type JITDumpRecordCodeLoad struct {
	PID       uint32 // OS process id of the runtime generating the jitted code
	TID       uint32 // OS thread identification of the runtime thread generating the jitted code
	VMA       uint64 // virtual address of jitted code start
	CodeAddr  uint64 // code start address for the jitted code. By default vma = code_addr
	CodeSize  uint64 // size in bytes of the generated jitted code
	CodeIndex uint64 // unique identifier for the jitted code
}

func ReadJITDumpHeader(file io.ReadSeeker) (*JITDumpHeader, error) {
	header := JITDumpHeader{}
	err := binary.Read(file, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}

	if header.Magic != 0x4A695444 {
		return nil, fmt.Errorf("File malformed, or maybe wrong endianness. Found magic number: %x", header.Magic)
	}

	return &header, nil
}

func ReadJITDumpRecordHeader(file io.ReadSeeker) (*JITDumpRecordHeader, error) {
	header := JITDumpRecordHeader{}
	err := binary.Read(file, binary.LittleEndian, &header)
	if err != nil {
		return nil, err
	}
	return &header, nil
}

func ReadJITDumpRecordCodeLoad(file io.ReadSeeker, header *JITDumpRecordHeader) (*JITDumpRecordCodeLoad, string, error) {
	record := JITDumpRecordCodeLoad{}
	err := binary.Read(file, binary.LittleEndian, &record)
	if err != nil {
		return nil, "", err
	}

	recordHeaderSize := uint32(16)
	codeLoadRecordHeaderSize := uint32(40)
	nameSize := header.TotalSize - uint32(record.CodeSize) - recordHeaderSize - codeLoadRecordHeaderSize
	name := make([]byte, nameSize)
	err = binary.Read(file, binary.LittleEndian, &name)
	if err != nil {
		return nil, "", err
	}

	if name[nameSize-1] != '\x00' {
		return nil, "", fmt.Errorf("Expected null terminated string, found %c", name[nameSize-1])
	}

	// Skip over the actual native code because we don't need it but we
	// probably do want to read the next record.
	_, err = file.Seek(int64(record.CodeSize), io.SeekCurrent)
	if err != nil {
		return nil, "", err
	}

	return &record, string(name), nil
}

func SkipJITDumpRecord(file io.ReadSeeker, header *JITDumpRecordHeader) error {
	recordHeaderSize := uint64(16)
	_, err := file.Seek(int64(header.TotalSize)-int64(recordHeaderSize), io.SeekCurrent)
	if err != nil {
		return err
	}
	return nil
}
