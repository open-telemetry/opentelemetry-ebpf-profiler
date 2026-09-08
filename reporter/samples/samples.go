// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

import (
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type TraceEventMeta struct {
	Comm           libpf.Comm
	ExecutablePath libpf.String
	ContainerID    libpf.String
	EnvVars        map[libpf.String]libpf.String
	// ExtraMeta holds key-value pairs produced by a processmanager.ProcessMetaEnricher.
	// It is nil when no enricher is configured. Consumers can access this via
	// SampleAttrProducer.CollectExtraSampleMeta to attach process-level attributes.
	ExtraMeta      map[libpf.String]string
	APMServiceName string
	ResourceAttrs  attribute.Set
	Timestamp      libpf.UnixTime64
	CPU            uint32
	ProfileType    *TypeMetadata
	Value          int64
	// ValueExtra carries origin-specific auxiliary values alongside Value,
	// mirroring libpf.EbpfTrace.ValueExtra (populated in eBPF). It is kept
	// generic so probes other than heap (e.g. OOM) can report additional
	// information without a bespoke field. For heap alloc events,
	// ValueExtra[1] is the raw, un-weighted allocation size in bytes; combined
	// with Value (the byte-weighted estimator) it lets consumers derive an
	// unbiased object-count estimate. Zero for origins that carry no extra
	// values.
	ValueExtra [2]uint64
	PID, TID   libpf.PID
	SpanID     libpf.APMSpanID
	TraceID    libpf.APMTraceID
}

// TraceEvents holds known information about a trace.
type TraceEvents struct {
	Labels     map[libpf.String]libpf.String
	Frames     libpf.Frames
	Timestamps []uint64 // in nanoseconds
	Values     []int64
	// ValuesExtra holds the per-event TraceEventMeta.ValueExtra. It is either
	// empty, for origins declaring TypeMetadata.ValueExtraFields == 0, or the
	// same length as Values and index-aligned with it. Origins that do declare
	// extras always append, zero-valued or not, so ValuesExtra[i] always
	// belongs to Values[i] (e.g. heap alloc, where ValuesExtra[i][1] is the
	// allocation size).
	ValuesExtra [][2]uint64
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

	// ResourceAttrs are the OTel resource attributes from ProcessContext,
	// if available. Deliberately not part of ResourceKey: refreshing them as
	// samples arrive lets a late-detected process context apply to the whole
	// reporting period. The latest value always wins, an empty one included,
	// so a cleared context drops attribution instead of leaving it stale.
	ResourceAttrs attribute.Set

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

	// ValueExtraFields is the number of leading TraceEventMeta.ValueExtra
	// elements this origin populates. Zero, the default, means the origin
	// reports no auxiliary values and TraceEvents.ValuesExtra stays nil.
	//
	// We have to specify this separately so we can identify the case where
	// ValuesExtra legitimately contains zeroes.
	ValueExtraFields int

	// ReportValues indicates whether a sample's value should be included
	// in the exported sample (e.g. off-CPU durations).
	ReportValues bool
}
