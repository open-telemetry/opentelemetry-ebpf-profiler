// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type TraceEventMeta struct {
	Comm           libpf.Comm
	ProcessName    libpf.String
	ExecutablePath libpf.String
	ContainerID    libpf.String
	EnvVars        map[libpf.String]libpf.String
	APMServiceName string
	Timestamp      libpf.UnixTime64
	CPU            uint32
	ProfileType    *TypeMetadata
	Value          int64
	// AllocSize is the raw, un-weighted allocation size in bytes for
	// TraceOriginHeapAlloc events (see libpf.EbpfTrace.Size); combined with
	// Value (the byte-weighted estimator) it lets consumers derive an
	// unbiased object-count estimate. Zero/unused for all other origins.
	AllocSize int64
	PID, TID  libpf.PID
	SpanID    libpf.APMSpanID
	TraceID   libpf.APMTraceID
}

// TraceEvents holds known information about a trace.
type TraceEvents struct {
	Labels     map[libpf.String]libpf.String
	Frames     libpf.Frames
	Timestamps []uint64 // in nanoseconds
	Values     []int64
	// AllocSizes holds the per-event TraceEventMeta.AllocSize, index-aligned
	// with Values. Only populated for TraceOriginHeapAlloc.
	AllocSizes []int64
}

// TraceEventsTree stores samples and their related metadata in a tree-like
// structure optimized for the OTel Profiling protocol representation.
type TraceEventsTree map[ResourceKey]ResourceToProfiles

// ResourceToProfiles holds non-comparable information that belong to
// a resource as well as profiling event data of this resource.
type ResourceToProfiles struct {
	// EnvVars can not be part of ResourceKey as maps are not
	// comparable.
	EnvVars map[libpf.String]libpf.String

	// Events holds the actual profiling information.
	Events map[*TypeMetadata]SampleToEvents
}

// SampleToEvents maps a unique trace hash with its meta data to
// trace events.
type SampleToEvents map[SampleKey]*TraceEvents

// ResourceKey is the deduplication key for samples that describes a unique
// resource. This **must always** contain all trace fields that aren't
// already part of the trace hash to ensure that we don't accidentally merge
// traces with different fields.
type ResourceKey struct {
	// ContainerID represents an extracted key from /proc/<PID>/cgroup.
	ContainerID libpf.String

	// Executable path is retrieved from /proc/PID/exe
	ExecutablePath libpf.String

	// APMServiceName is provided by the eBPF programs
	APMServiceName string

	PID int64
}

// SampleKey holds a unique trace hash and its dedicated meta data.
type SampleKey struct {
	// ExtraMeta stores extra meta info that may have been produced by a
	// `SampleAttrProducer` instance. May be nil.
	ExtraMeta any

	// Comm is provided by the eBPF programs
	Comm libpf.Comm

	Hash libpf.TraceHash

	TID int64
	CPU int64

	SpanID  libpf.APMSpanID
	TraceID libpf.APMTraceID
}

// SourceProfile is a set of samples sharing the same sample type schema,
// produced by a probe's SampleSource implementation at each collection interval.
type SourceProfile struct {
	// SampleTypes describes each value column (name + unit).
	SampleTypes []SourceSampleType
	// Samples are the data rows.
	Samples []SourceSample
}

// SourceSampleType describes a single value column in a SourceProfile.
type SourceSampleType struct {
	Type string // e.g. "inuse_space"
	Unit string // e.g. "bytes"
}

// SourceSample is a single sample row produced by a SampleSource probe.
type SourceSample struct {
	PID       libpf.PID
	TraceHash libpf.TraceHash
	Frames    libpf.Frames
	Values    []int64 // one per SampleType, positional
}

// TypeMetadata describes how profiling events of a particular kind
// should be interpreted and exported as an OTel profile.
type TypeMetadata struct {
	// PeriodType describes what is measured per period (e.g. "cpu").
	// Empty means this profile type has no period (e.g. event-driven kinds).
	PeriodType string

	// PeriodUnit is the unit for PeriodType (e.g. "nanoseconds").
	PeriodUnit string

	// SampleType describes what a single sample represents (e.g. "samples").
	SampleType string

	// SampleUnit is the unit for SampleType (e.g. "count").
	SampleUnit string

	// ReportValues indicates whether a sample's value should be included
	// in the exported sample (e.g. off-CPU durations).
	ReportValues bool
}
