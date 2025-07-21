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

	File   FileID
	Lineno AddressOrLineno

	MappingStart      Address
	MappingEnd        Address
	MappingFileOffset uint64
}

// Frames is a list of frames
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
	// make unique frame
	frame := unique.Make(Frame{
		Type:              ty,
		File:              file,
		Lineno:            addrOrLine,
		MappingStart:      mappingStart,
		MappingEnd:        mappingEnd,
		MappingFileOffset: mappingFileOffset,
	})
	trace.Frames = append(trace.Frames, frame)
}
