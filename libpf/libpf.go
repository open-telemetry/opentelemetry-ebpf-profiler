// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

// UnixTime64 represents nanoseconds since epoch.
type UnixTime64 uint64

// AddressOrLineno represents a line number in an interpreted file or an offset into
// a native file.
type AddressOrLineno uint64

// Void allows to use maps as sets without memory allocation for the values.
// From the "Go Programming Language":
//
//	The struct type with no fields is called the empty struct, written struct{}. It has size zero
//	and carries no information but may be useful nonetheless. Some Go programmers
//	use it instead of bool as the value type of a map that represents a set, to emphasize
//	that only the keys are significant, but the space saving is marginal and the syntax more
//	cumbersome, so we generally avoid it.
type Void struct{}

// SourceLineno represents a line number within a source file. It is intended to be used for the
// source line numbers associated with offsets in native code, or for source line numbers in
// interpreted code.
type SourceLineno uint64

// SourceColumn represents a column number within a source file line. It is intended to be used
// for the source column numbers in interpreted code.
type SourceColumn uint64

// Origin determines the source of a trace.
type Origin uint16

// ProfileTypeMetadata describes how profiling events of a particular kind
// should be interpreted and exported as an OTel profile.
type ProfileTypeMetadata struct {
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

// Temporary list of well-known profile types.
var (
	ProfileTypeSampling = &ProfileTypeMetadata{
		PeriodType: "cpu",
		PeriodUnit: "nanoseconds",
		SampleType: "samples",
		SampleUnit: "count",
	}
	ProfileTypeOffCPU = &ProfileTypeMetadata{
		SampleType:   "off_cpu",
		SampleUnit:   "nanoseconds",
		ReportValues: true,
	}
	ProfileTypeProbe = &ProfileTypeMetadata{
		SampleType: "events",
		SampleUnit: "count",
	}
)
