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
	// ContextValues aliases the origin-specific value prefix in the pooled
	// libpf.EbpfTrace. It is valid only while the trace event is being handled
	// and must not be retained by the reporter.
	ContextValues []uint64
	PID, TID      libpf.PID
	SpanID        libpf.APMSpanID
	TraceID       libpf.APMTraceID
}

// TraceEvents holds known information about a trace.
type TraceEvents struct {
	Labels     map[libpf.String]libpf.String
	Frames     libpf.Frames
	Timestamps []uint64 // in nanoseconds
	// Values stores one contiguous group per event, with one value for each
	// TypeMetadata.SampleTypes entry. Groups are index-aligned with Timestamps.
	Values []int64
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

// SampleType describes one profile emitted from an event type: what its
// sample values measure, their unit, and how the profile was sampled.
type SampleType struct {
	// Type describes what the sample values measure (e.g. "samples").
	Type string

	// Unit is the unit of the sample values (e.g. "count").
	Unit string

	// Period is the profile's sampling period. Nil means the profile has no
	// period (e.g. event-driven kinds).
	Period *Period
}

// SnapshotProfile is a set of snapshot samples produced by a probe's
// SnapshotSource implementation at each collection interval. The reporter folds
// them into the TraceEventsTree so they share the event-driven export path.
type SnapshotProfile struct {
	// ProfileType describes how the samples are exported. Snapshot profiles
	// normally set OmitThreadContext, having no per-thread attribution.
	ProfileType *TypeMetadata
	Samples     []SnapshotSample
}

// SnapshotSample is a single sample row produced by a SnapshotSource probe.
type SnapshotSample struct {
	PID           libpf.PID
	TraceHash     libpf.TraceHash
	Frames        libpf.Frames
	ContextValues []uint64
}

// ProcessMeta holds per-process metadata needed when building OTLP resource
// attributes for profile export.
type ProcessMeta struct {
	ExecutablePath libpf.String
	ContainerID    libpf.String
}

// Period describes how a profile was sampled.
type Period struct {
	// Type describes what is measured per period (e.g. "cpu").
	Type string

	// Unit is the unit of Type and Value (e.g. "nanoseconds").
	Unit string

	// Value is the sampling period, in Unit.
	Value int64
}

// TypeMetadata describes how profiling events of a particular kind should be
// interpreted and exported as OTel profiles.
type TypeMetadata struct {
	// SampleTypes has one entry per profile emitted from this event type.
	SampleTypes []SampleType

	// ReportValues indicates whether sample values should be included in the
	// exported profiles (e.g. off-CPU durations).
	ReportValues bool

	// DeriveValues appends one reportable value per SampleTypes entry for a
	// single event. Nil appends int64(meta.ContextValues[0]), or 0 if there are
	// no context values. The function must consume ContextValues synchronously
	// because they may alias a pooled trace.
	DeriveValues func(dst []int64, meta *TraceEventMeta) []int64

	// OmitThreadContext suppresses the per-sample thread and CPU attributes.
	// Interval snapshots aggregate across threads and have no meaningful TID
	// or CPU, so emitting zeros for them would misattribute the samples.
	OmitThreadContext bool
}

// AppendValues appends the reportable values for one event.
func (m *TypeMetadata) AppendValues(dst []int64, meta *TraceEventMeta) []int64 {
	if m.DeriveValues != nil {
		return m.DeriveValues(dst, meta)
	}
	if len(meta.ContextValues) == 0 {
		// Keep Values aligned with Timestamps for origins without a value.
		return append(dst, 0)
	}
	return append(dst, int64(meta.ContextValues[0]))
}
