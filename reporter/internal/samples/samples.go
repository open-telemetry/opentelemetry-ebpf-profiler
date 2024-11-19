// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"

import "go.opentelemetry.io/ebpf-profiler/libpf"

// TraceEvents holds known information about a trace.
type TraceEvents struct {
	Files              []libpf.FileID
	Linenos            []libpf.AddressOrLineno
	FrameTypes         []libpf.FrameType
	MappingStarts      []libpf.Address
	MappingEnds        []libpf.Address
	MappingFileOffsets []uint64
	Timestamps         []uint64 // in nanoseconds
}

// TraceAndMetaKey is the deduplication key for samples. This **must always**
// contain all trace fields that aren't already part of the trace hash to ensure
// that we don't accidentally merge traces with different fields.
type TraceAndMetaKey struct {
	Hash libpf.TraceHash
	// comm and apmServiceName are provided by the eBPF programs
	Comm           string
	ApmServiceName string
	// containerID is annotated based on PID information
	ContainerID string
	Pid         int64
}

// AttrKeyValue is a helper to populate Profile.attribute_table.
type AttrKeyValue[T string | int64] struct {
	Key string
	// Set to true for OTel SemConv attributes with requirement level: Required
	Required bool
	Value    T
}

// ExecInfo enriches an executable with additional metadata.
type ExecInfo struct {
	FileName   string
	GnuBuildID string
}

// SourceInfo allows mapping a frame to its source origin.
type SourceInfo struct {
	LineNumber     libpf.SourceLineno
	FunctionOffset uint32
	FunctionName   string
	FilePath       string
}

// FuncInfo is a helper to construct profile.Function messages.
type FuncInfo struct {
	Name     string
	FileName string
}
