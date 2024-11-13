// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package host implements types and methods specific to interacting with eBPF maps.
package host // import "go.opentelemetry.io/ebpf-profiler/host"

import (
	"encoding/binary"
	"fmt"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/times"
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

// FileIDFromLibpf truncates a libpf.FileID to be a host.FileID.
func FileIDFromLibpf(id libpf.FileID) FileID {
	return FileID(id.Hi())
}

type Frame struct {
	File          FileID
	Lineno        libpf.AddressOrLineno
	Type          libpf.FrameType
	ReturnAddress bool
}

type Trace struct {
	Comm             string
	Frames           []Frame
	Hash             TraceHash
	KTime            times.KTime
	PID              libpf.PID
	TID              libpf.PID
	Origin           int
	OffTime          uint64 // Time a task was off-cpu.
	APMTraceID       libpf.APMTraceID
	APMTransactionID libpf.APMTransactionID
	Registers        Regs
}

type Regs struct {
	R15    uint64
	R14    uint64
	R13    uint64
	R12    uint64
	Bp     uint64
	Bx     uint64
	R11    uint64
	R10    uint64
	R9     uint64
	R8     uint64
	Ax     uint64
	Cx     uint64
	Dx     uint64
	Si     uint64
	Di     uint64
	OrigAx uint64
	Ip     uint64
	Cs     uint64
	Flags  uint64
	Sp     uint64
	Ss     uint64
}
