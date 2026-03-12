// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package samples // import "go.opentelemetry.io/ebpf-profiler/reporter/samples"

import (
	"go.opentelemetry.io/ebpf-profiler/libpf"
)

type TraceEventMeta struct {
	Timestamp      libpf.UnixTime64
	Comm           libpf.String
	ProcessName    libpf.String
	ExecutablePath libpf.String
	APMServiceName string
	ContainerID    libpf.String
	PID, TID       libpf.PID
	CPU            int
	Origin         libpf.Origin
	OffTime        int64
	EnvVars        map[libpf.String]libpf.String
}

// TraceEvents holds known information about a trace.
type TraceEvents struct {
	Frames     libpf.Frames
	Timestamps []uint64 // in nanoseconds
	OffTimes   []int64  // in nanoseconds
	Labels     map[libpf.String]libpf.String
}

// TraceEventsTree stores samples and their related metadata in a tree-like
// structure optimized for the OTel Profiling protocol representation.
type TraceEventsTree map[ResourceKey]ResourceToProfiles

// ResourceToProfiles holds non-comparable information that belong to
// a resource as well as profiling event data of this resource.
type ResourceToProfiles struct {
	EnvVars map[libpf.String]libpf.String

	// ExtraMeta stores extra meta info that may have been produced by a
	// `SampleAttrProducer` instance. May be nil.
	ExtraMeta any

	// Events holds the actual profiling information.
	Events map[libpf.Origin]HashToEvents
}

type HashToEvents map[libpf.TraceHash]*TraceEvents

// ResourceKey is the deduplication key for samples that describes a unique
// resource. This **must always** contain all trace fields that aren't
// already part of the trace hash to ensure that we don't accidentally merge
// traces with different fields.
type ResourceKey struct {
	// comm and apmServiceName are provided by the eBPF programs
	Comm           libpf.String
	ApmServiceName string
	// ContainerID represents an extracted key from /proc/<PID>/cgroup.
	ContainerID libpf.String
	Pid         int64
	Tid         int64
	CPU         int64
	// Process name is retrieved from /proc/PID/comm
	// TODO (flo): ProcessName was never used - verify its use
	ProcessName libpf.String
	// Executable path is retrieved from /proc/PID/exe
	ExecutablePath libpf.String
}
