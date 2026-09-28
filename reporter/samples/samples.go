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
	// generic so any origin can attach additional per-sample data without a
	// bespoke field. Whether these values are recorded, and how many entries
	// are meaningful, is declared by ProfileType.ValueExtraLen. Zero for
	// origins that carry no extra values.
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
	// ValuesExtra holds the per-event TraceEventMeta.ValueExtra, index-aligned
	// with Values. Populated only for profile types that declare
	// ValueExtraLen > 0; in that case the append is unconditional so the slice
	// stays aligned with Values even when a sample's extra values are all zero.
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

	// ReportValues indicates whether a sample's value should be included
	// in the exported sample (e.g. off-CPU durations).
	ReportValues bool

	// ValueExtraLen declares how many leading entries of a sample's ValueExtra
	// carry meaningful data for this profile type. Zero means ValueExtra is
	// unused and must not be recorded. When > 0, the reporter records
	// ValueExtra for every sample (including all-zero ones) so that
	// TraceEvents.ValuesExtra stays index-aligned with Values.
	ValueExtraLen int

	// DerivedProfiles are additional profiles emitted from the same event set,
	// each computed by transforming a sample's primary Value (and its
	// ValueExtra). Empty for origins that emit a single profile.
	DerivedProfiles []DerivedProfile
}

// DerivedProfile describes an additional profile produced from the same
// events as its parent TypeMetadata. It lets a probe declare a secondary
// view (for example an object-count derived from a byte-weighted value)
// without the reporter needing to know the semantics: the reporter simply
// applies Value to each sample.
type DerivedProfile struct {
	// SampleType and SampleUnit name the derived profile's value axis.
	SampleType string
	SampleUnit string

	// Value derives one output value from a sample's primary value and its
	// ValueExtra.
	Value func(value int64, extra [2]uint64) int64
}
