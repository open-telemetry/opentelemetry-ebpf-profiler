// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"unique"
)

// FrameMappingFileData represents a backing file for a memory mapping.
type FrameMappingFileData struct {
	// FileID is the hash of the file.
	FileID FileID
	// FileName is the base filename of the executable.
	FileName String
	// GnuBuildID is the GNU build ID from .note.gnu.build-id, if any.
	GnuBuildID string
	// GoBuildID is the Go build ID from .note.go.buildid, if any.
	GoBuildID string
}

// FrameMappingFile is an interned FrameMappingFileData reference.
type FrameMappingFile struct {
	value unique.Handle[FrameMappingFileData]
}

// NewFrameMappingFile interns given FrameMappingFileData.
func NewFrameMappingFile(data FrameMappingFileData) FrameMappingFile {
	return FrameMappingFile{value: unique.Make(data)}
}

// Value returns the dereferences FrameMappingFileData.
func (fmf FrameMappingFile) Value() FrameMappingFileData {
	return fmf.value.Value()
}

// FrameMappingData contains file backed mapping data.
type FrameMappingData struct {
	// File is a reference to data about the backing file.
	File FrameMappingFile
	// Start contains the mapping start address (file virtual address).
	Start Address
	// End contains the mapping end address (file virtual address).
	End Address
	// FileOffset is the offset within the file for this mapping.
	FileOffset uint64
}

// FrameMapping is an interned FrameMappingData reference.
type FrameMapping struct {
	value unique.Handle[FrameMappingData]
}

// NewFrameMapping interns given FrameMappingData.
func NewFrameMapping(data FrameMappingData) FrameMapping {
	return FrameMapping{value: unique.Make(data)}
}

// Valid determines if the FrameMapping is valid.
func (fmf FrameMapping) Valid() bool {
	return fmf != FrameMapping{}
}

// Value returns the dereferenced FrameMappingData.
// This can be done only if it the FrameMapping is Valid.
func (fmf FrameMapping) Value() FrameMappingData {
	return fmf.value.Value()
}

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
	// An address in ELF VA space (native frame) or line number (interpreted frame).
	AddressOrLineno AddressOrLineno
	// Mapping is a reference to the mapping data to which this Frame corresponds to.
	// Available only for frames executing on a file backed memory mapping.
	Mapping FrameMapping
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
	CustomLabels map[String]String
}
