// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"unique"
)

// Frame represents one frame in a stack trace.
type Frame struct {
	// Type is the frame type.
	Type FrameType
	// FunctionOffset is the line offset from function start line for the frame.
	FunctionOffset uint32
	// FunctionName is the name of the function for the frame.
	FunctionName String
	// SourceFile is the source code file name for the frame.
	SourceFile String
	// SourceLine is the source code level line number of this frame.
	SourceLine SourceLineno

	// Calculated executable FileID for the backing mapping file.
	FileID FileID
	// An address in ELF VA space (native frame) or line number (interpreted frame).
	AddressOrLineno AddressOrLineno

	MappingStart      Address
	MappingEnd        Address
	MappingFileOffset uint64
}

// Frames is a list of interned frames.
type Frames []unique.Handle[Frame]

// Append interns and appends a frame to the slice of frames.
func (frames *Frames) Append(frame *Frame) {
	*frames = append(*frames, unique.Make(*frame))
}

// Trace represents a stack trace.
type Trace struct {
	Frames       Frames
	Hash         TraceHash
	CustomLabels map[string]string
}

// AppendFrame appends a frame to the columnar frame array without mapping information.
func (trace *Trace) AppendFrame(ty FrameType, file FileID, addrOrLine AddressOrLineno) {
	trace.AppendFrameFull(ty, file, addrOrLine, 0, 0, 0)
}

// AppendFrameFull appends a frame with mapping info to the columnar frame array.
func (trace *Trace) AppendFrameFull(ty FrameType, file FileID, addrOrLine AddressOrLineno,
	mappingStart Address, mappingEnd Address, mappingFileOffset uint64) {
	trace.Frames.Append(&Frame{
		Type:              ty,
		FileID:            file,
		AddressOrLineno:   addrOrLine,
		MappingStart:      mappingStart,
		MappingEnd:        mappingEnd,
		MappingFileOffset: mappingFileOffset,
	})
}
