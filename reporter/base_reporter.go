// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"errors"
	"fmt"
	"time"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
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

	// collectionStartTime tracks when the current collection window started.
	// Initialized when Start() is called. The duration of the first profile may be
	// slightly overestimated as it includes tracer setup time before samples arrive.
	collectionStartTime time.Time
}

var errUnknownProfileType = errors.New("unknown trace profile type")

func (b *baseReporter) Stop() {
	b.runLoop.Stop()
}

func countHeapProfileEvents(tree samples.TraceEventsTree) (stacks, samplesCount int, valueSum int64) {
	for _, resource := range tree {
		for profileType, sampleEvents := range resource.Events {
			valueIndex := -1
			for i, sampleType := range profileType.SampleTypes {
				if sampleType.Type == "alloc_space" {
					valueIndex = i
					break
				}
			}
			if valueIndex < 0 {
				continue
			}
			valueWidth := len(profileType.SampleTypes)
			for _, events := range sampleEvents {
				stacks++
				samplesCount += len(events.Timestamps)
				for i := valueIndex; i < len(events.Values); i += valueWidth {
					valueSum += events.Values[i]
				}
			}
		}
	}
	return stacks, samplesCount, valueSum
}

func (b *baseReporter) ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error {
	if meta.ProfileType == nil {
		return fmt.Errorf("skip reporting trace: %w", errUnknownProfileType)
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
	traceHash := trace.Hash()

	eventsTree := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&eventsTree)

	if _, exists := (*eventsTree)[key]; !exists {
		(*eventsTree)[key] = samples.ResourceToProfiles{
			EnvVars: meta.EnvVars,
			Events:  make(map[*samples.TypeMetadata]samples.SampleToEvents),
		}
	}

	rtp := (*eventsTree)[key]
	// Compared by hash to skip the map write-back when nothing changed.
	if meta.ResourceAttrs.Equivalent() != rtp.ResourceAttrs.Equivalent() {
		rtp.ResourceAttrs = meta.ResourceAttrs
		(*eventsTree)[key] = rtp
	}
	if _, exists := rtp.Events[meta.ProfileType]; !exists {
		rtp.Events[meta.ProfileType] = make(samples.SampleToEvents)
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
	if events, exists := rtp.Events[meta.ProfileType][sampleKey]; exists {
		values, err := appendEventValues(events.Values, meta)
		if err != nil {
			return err
		}
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		events.Values = values
		return nil
	}

	values, err := appendEventValues(nil, meta)
	if err != nil {
		return err
	}
	rtp.Events[meta.ProfileType][sampleKey] = &samples.TraceEvents{
		Frames:     trace.Frames,
		Timestamps: []uint64{uint64(meta.Timestamp)},
		Values:     values,
		Labels:     trace.CustomLabels,
	}
	return nil
}

// appendEventValues applies the event type's transform and verifies its fixed
// output width before the values become index-aligned with a timestamp.
func appendEventValues(dst []int64, meta *samples.TraceEventMeta) ([]int64, error) {
	start := len(dst)
	values := meta.ProfileType.AppendValues(dst, meta)
	got := len(values) - start
	want := len(meta.ProfileType.SampleTypes)
	if got != want {
		return dst, fmt.Errorf("profile value transform appended %d values, expected %d", got, want)
	}
	return values, nil
}

// SetSnapshotSources sets the callback for collecting probe-produced snapshots.
func (b *baseReporter) SetSnapshotSources(fn func() []samples.SnapshotProfile) {
	b.cfg.SnapshotSources = fn
}

// SetProcessMetaForPID sets the process metadata resolver for profile resource attributes.
func (b *baseReporter) SetProcessMetaForPID(fn func(libpf.PID) samples.ProcessMeta) {
	b.cfg.ProcessMetaForPID = fn
}

// mergeSnapshots folds probe-produced snapshot samples into tree so they are
// transformed and exported by the same path as event-driven samples.
//
// Snapshot rows describe the state of a process at one instant rather than
// individual events, so they carry no thread, CPU or per-event timestamp: their
// SampleKey holds only the trace hash, and ts (the collection interval end) is
// used as the single timestamp.
func (b *baseReporter) mergeSnapshots(tree samples.TraceEventsTree, ts time.Time) {
	if b.cfg.SnapshotSources == nil {
		return
	}

	timestamp := uint64(ts.UnixNano())
	for _, sp := range b.cfg.SnapshotSources() {
		if sp.ProfileType == nil {
			log.Warnf("Skipping snapshot profile with no profile type")
			continue
		}
		for _, row := range sp.Samples {
			events := b.snapshotEventsFor(tree, sp.ProfileType, row)
			sampleKey := samples.SampleKey{Hash: row.TraceHash}
			meta := &samples.TraceEventMeta{
				ProfileType:   sp.ProfileType,
				ContextValues: row.ContextValues,
			}
			if existing, ok := events[sampleKey]; ok {
				values, err := appendEventValues(existing.Values, meta)
				if err != nil {
					log.Warnf("Skipping snapshot sample: %v", err)
					continue
				}
				existing.Timestamps = append(existing.Timestamps, timestamp)
				existing.Values = values
				continue
			}
			values, err := appendEventValues(nil, meta)
			if err != nil {
				log.Warnf("Skipping snapshot sample: %v", err)
				continue
			}
			events[sampleKey] = &samples.TraceEvents{
				Frames:     row.Frames,
				Timestamps: []uint64{timestamp},
				Values:     values,
			}
		}
	}
}

// snapshotEventsFor returns the SampleToEvents map for row's process and profile
// type, creating the resource and profile-type entries if this is the first
// snapshot sample for them.
func (b *baseReporter) snapshotEventsFor(tree samples.TraceEventsTree,
	profileType *samples.TypeMetadata, row samples.SnapshotSample,
) samples.SampleToEvents {
	key := samples.ResourceKey{PID: int64(row.PID)}
	if b.cfg.ProcessMetaForPID != nil {
		meta := b.cfg.ProcessMetaForPID(row.PID)
		key.ExecutablePath = meta.ExecutablePath
		key.ContainerID = meta.ContainerID
	}

	rtp, ok := tree[key]
	if !ok {
		rtp = samples.ResourceToProfiles{
			Events: make(map[*samples.TypeMetadata]samples.SampleToEvents),
		}
		tree[key] = rtp
	}
	if _, ok := rtp.Events[profileType]; !ok {
		rtp.Events[profileType] = make(samples.SampleToEvents)
	}
	return rtp.Events[profileType]
}
