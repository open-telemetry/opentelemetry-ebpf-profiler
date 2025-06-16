/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

// Package host implements types and methods specific to interacting with eBPF maps.
package host

import (
	"encoding/binary"
	"fmt"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/pfelf"
	"github.com/elastic/otel-profiling-agent/times"
)

// TraceHash is used for unique identifiers for traces, and is required to be 64-bits
// due to the constraints imposed by the eBPF maps, unlike the larger TraceHash used
// outside the host agent.
type TraceHash uint64

// FileID is used for unique identifiers for files, and is required to be 64-bits
// due to the constraints imposed by the eBPF maps, unlike the larger FileID used
// outside the host agent.
type FileID uint64

// FileIDFromBytes parses a byte slice into the internal data representation for a file ID.
func FileIDFromBytes(b []byte) (FileID, error) {
	if len(b) != 8 {
		return FileID(0), fmt.Errorf("invalid length for bytes '%v': %d", b, len(b))
	}
	return FileID(binary.BigEndian.Uint64(b[0:8])), nil
}

func (fid FileID) StringNoQuotes() string {
	return fmt.Sprintf("%016x%016x", uint64(fid), uint64(fid))
}

// CalculateKernelFileID calculates an ID for a kernel image or module given its libpf.FileID.
func CalculateKernelFileID(id libpf.FileID) FileID {
	return FileID(id.Hi())
}

// CalculateID calculates a 64-bit executable ID of the contents of a file.
func CalculateID(fileName string) (FileID, error) {
	hash, err := pfelf.FileHash(fileName)
	if err != nil {
		return FileID(0), err
	}
	return FileIDFromBytes(hash[0:8])
}

type Frame struct {
	File   FileID
	Lineno libpf.AddressOrLineno
	Type   libpf.FrameType
}

type Trace struct {
	Comm   string
	Frames []Frame
	Hash   TraceHash
	KTime  times.KTime
	PID    libpf.PID
}
