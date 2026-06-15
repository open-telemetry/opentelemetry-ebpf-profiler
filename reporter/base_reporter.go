// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/traceutil"
)

// baseReporter encapsulates shared behavior between all the available reporters.
type baseReporter struct {
	cfg *Config

	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// runLoop handles the run loop
	runLoop *runLoop

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[samples.TraceEventsTree]

	// registeredTypes maps known origin IDs to their profile type metadata. It is
	// populated by RegisterProfileType.
	registeredTypes xsync.RWMutex[map[libpf.Origin]samples.ProfileTypeMetadata]

	// collectionStartTime tracks when the current collection window started.
	// Initialized when Start() is called. The duration of the first profile may be
	// slightly overestimated as it includes tracer setup time before samples arrive.
	collectionStartTime time.Time
}

var (
	ErrUnknownOrigin       = errors.New("unknown trace origin")
	ErrOriginAlreadyExists = errors.New("profile origin already registered")
)

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
}

// RegisterProfileType registers a profiling origin and its associated metadata
// with the reporter. It must be called for each origin before the first
// ReportTraceEvent call for that origin.
//
// Returns ErrOriginAlreadyExists if the origin was already registered.
// Returns an error if meta is inconsistent.
func (b *baseReporter) RegisterProfileType(origin libpf.Origin, meta samples.ProfileTypeMetadata) error {
	if (meta.PeriodType == "") != (meta.PeriodUnit == "") {
		return fmt.Errorf("PeriodType and PeriodUnit must both be set or both be empty."+
			" Got PeriodType=%q with PeriodUnit=%q.", meta.PeriodType, meta.PeriodUnit)
	}
	if (meta.SampleType == "") != (meta.SampleUnit == "") {
		return fmt.Errorf("SampleType and SampleUnit must both be set or both be empty."+
			" Got SampleType=%q with SampleUnit=%q.", meta.SampleType, meta.SampleUnit)
	}

	m := b.registeredTypes.WLock()
	defer b.registeredTypes.WUnlock(&m)

	if _, exists := (*m)[origin]; exists {
		return fmt.Errorf("origin %d: %w", origin, ErrOriginAlreadyExists)
	}

	(*m)[origin] = meta
	return nil
}

// generate creates an OTLP Profiles payload from the given trace events tree.
// It uses the registered profile types to determine iteration order and
// populate per-profile metadata.
func (b *baseReporter) generate(
	tree samples.TraceEventsTree,
	collectionStart, collectionEnd time.Time,
) (pprofile.Profiles, error) {
	typesPtr := b.registeredTypes.RLock()
	profileTypes := make(map[libpf.Origin]samples.ProfileTypeMetadata, len(*typesPtr))
	for k, v := range *typesPtr {
		profileTypes[k] = v
	}
	b.registeredTypes.RUnlock(&typesPtr)
	return b.pdata.Generate(tree, profileTypes, b.name, b.version, collectionStart, collectionEnd)
}

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	types := b.registeredTypes.RLock()
	_, known := (*types)[meta.Origin]
	b.registeredTypes.RUnlock(&types)

	if !known {
		return fmt.Errorf("skip reporting trace for %d origin: %w", meta.Origin,
			ErrUnknownOrigin)
	}

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	key := samples.ResourceKey{
		APMServiceName: meta.APMServiceName,
		ContainerID:    meta.ContainerID,
		PID:            int64(meta.PID),
		ExecutablePath: meta.ExecutablePath,
	}
	traceHash := traceutil.HashTrace(trace)

	eventsTree := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&eventsTree)

	if _, exists := (*eventsTree)[key]; !exists {
		(*eventsTree)[key] = samples.ResourceToProfiles{
			EnvVars: meta.EnvVars,
			Events:  make(map[libpf.Origin]samples.SampleToEvents),
		}
	}

	rtp := (*eventsTree)[key]
	if _, exists := rtp.Events[meta.Origin]; !exists {
		rtp.Events[meta.Origin] = make(samples.SampleToEvents)
	}

	sampleKey := samples.SampleKey{
		Hash:      traceHash,
		Comm:      meta.Comm,
		TID:       int64(meta.TID),
		CPU:       int64(meta.CPU),
		SpanID:    meta.SpanID,
		TraceID:   meta.TraceID,
		ExtraMeta: extraMeta,
	}
	if events, exists := rtp.Events[meta.Origin][sampleKey]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.Values = append(events.Values, meta.Value)
		return nil
	}

	rtp.Events[meta.Origin][sampleKey] = &samples.TraceEvents{
		Frames:     trace.Frames,
		Timestamps: []uint64{uint64(meta.Timestamp)},
		Values:     []int64{meta.Value},
		Labels:     trace.CustomLabels,
	}
	return nil
}
