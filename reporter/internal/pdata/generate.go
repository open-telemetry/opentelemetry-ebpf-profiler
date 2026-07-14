// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/otel/attribute"

	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

const (
	ExecutableCacheLifetime = 1 * time.Hour
)

// profileKind is a sub-profile discriminator used when a single origin
// produces more than one OTLP Profile message from the same event set.
// For example, TraceOriginHeapAlloc emits both an alloc_space (bytes) and
// an alloc_objects (count) profile; the kind tells setProfile which
// value-type semantics to apply. Origins that emit only one profile use
// profileKindDefault. The type is intentionally generic so future origins
// can extend it without changing the setProfile signature.
type profileKind uint8

const (
	profileKindDefault profileKind = iota
	profileKindHeapAllocObjects
)

// sampleKeys returns the sample keys of events. When sortKeys is true the
// keys are returned in a deterministic order (via compareSampleKeys).
//
// Deterministic ordering matters when a single event map is rendered into
// more than one Profile message (currently: alloc_space + alloc_objects).
// Downstream consumers that want to correlate the two profiles (e.g. to
// compute average object size = space[i]/objects[i]) can do so by index
// only when both profiles list their samples in the same order. The sort
// guarantees that property. It is NOT a general contract that arbitrary
// profiles share index alignment; consumers must not assume it unless
// the profiles are explicitly documented as paired.
//
// Origins that produce only a single profile (CPU, off-CPU, probe) pass
// sortKeys=false to skip the sort entirely, so there is zero cost on
// those hot paths.
func sampleKeys(events samples.SampleToEvents, sortKeys bool) []samples.SampleKey {
	keys := make([]samples.SampleKey, 0, len(events))
	for sampleKey := range events {
		keys = append(keys, sampleKey)
	}
	if sortKeys {
		slices.SortFunc(keys, compareSampleKeys)
	}
	return keys
}

func compareSampleKeys(a, b samples.SampleKey) int {
	if n := cmp.Compare(a.Comm.String(), b.Comm.String()); n != 0 {
		return n
	}
	if a.Hash.Less(b.Hash) {
		return -1
	}
	if b.Hash.Less(a.Hash) {
		return 1
	}
	if n := cmp.Compare(a.TID, b.TID); n != 0 {
		return n
	}
	if n := cmp.Compare(a.CPU, b.CPU); n != 0 {
		return n
	}
	if n := slices.Compare(a.SpanID[:], b.SpanID[:]); n != 0 {
		return n
	}
	if n := slices.Compare(a.TraceID[:], b.TraceID[:]); n != 0 {
		return n
	}
	return cmp.Compare(fmt.Sprintf("%T:%#v", a.ExtraMeta, a.ExtraMeta),
		fmt.Sprintf("%T:%#v", b.ExtraMeta, b.ExtraMeta))
}

// Generate generates a pdata request out of internal profiles data, to be
// exported. The collectionStartTime and collectionEndTime define the time window
// during which the profiler was actively collecting samples.
func (p *Pdata) Generate(tree samples.TraceEventsTree,
	agentName, agentVersion string,
	collectionStartTime, collectionEndTime time.Time,
	sourceProfiles []samples.SourceProfile,
	processMeta func(libpf.PID) samples.ProcessMeta,
) (pprofile.Profiles, error) {
	profiles := pprofile.NewProfiles()
	dic := profiles.Dictionary()

	// Find oldest sample timestamp across all resources to handle buffered samples.
	adjustedStartTime := collectionStartTime
	for _, resourceToEvents := range tree {
		for _, traceEvents := range resourceToEvents.Events {
			for _, traceInfo := range traceEvents {
				for _, ts := range traceInfo.Timestamps {
					sampleTime := time.Unix(0, int64(ts))
					if sampleTime.Before(adjustedStartTime) {
						adjustedStartTime = sampleTime
					}
				}
			}
		}
	}
	if adjustedStartTime.Before(collectionStartTime) {
		log.Debugf("Adjusted profile start time backward by %v to include oldest sample",
			collectionStartTime.Sub(adjustedStartTime))
	}
	collectionStartTime = adjustedStartTime

	// Temporary helpers that will build the various tables in ProfilesDictionary.
	stringSet := make(orderedset.OrderedSet[string], 64)
	funcSet := make(orderedset.OrderedSet[funcInfo], 64)
	mappingSet := make(orderedset.OrderedSet[libpf.FrameMapping], 64)
	stackSet := make(orderedset.OrderedSet[stackInfo], 64)
	locationSet := make(orderedset.OrderedSet[locationInfo], 64)
	linkSet := make(orderedset.OrderedSet[linkInfo], 64)

	// By specification, the first element should be empty.
	stringSet.Add("")
	funcSet.Add(funcInfo{})
	mappingSet.Add(libpf.FrameMapping{})
	stackSet.Add(stackInfo{})
	locationSet.Add(locationInfo{})
	linkSet.Add(linkInfo{})

	dic.LinkTable().AppendEmpty()
	dic.MappingTable().AppendEmpty()
	dic.StackTable().AppendEmpty()
	dic.AttributeTable().AppendEmpty()
	dic.LocationTable().AppendEmpty()

	attrMgr := samples.NewAttrTableManager(stringSet, dic.AttributeTable())

	// Collect the profile types present anywhere in the tree once, in a stable
	// order, so that the order profiles are appended in is deterministic.
	seenProfileTypes := make(libpf.Set[*samples.TypeMetadata])
	for _, resourceToEvents := range tree {
		for profileType := range resourceToEvents.Events {
			if _, ok := seenProfileTypes[profileType]; !ok {
				seenProfileTypes[profileType] = libpf.Void{}
			}
		}
	}
	profileTypes := seenProfileTypes.ToSlice()
	slices.SortFunc(profileTypes, func(a, b *samples.TypeMetadata) int {
		if c := strings.Compare(a.SampleType, b.SampleType); c != 0 {
			return c
		}
		return strings.Compare(a.PeriodType, b.PeriodType)
	})

	for resource, toEvents := range tree {
		if len(toEvents.Events) == 0 {
			continue
		}

		rp := profiles.ResourceProfiles().AppendEmpty()
		setResourceAttributes(rp.Resource().Attributes(), resource, toEvents.EnvVars)
		rp.SetSchemaUrl(semconv.SchemaURL)

		sp := rp.ScopeProfiles().AppendEmpty()
		sp.Scope().SetName(agentName)
		sp.Scope().SetVersion(agentVersion)
		sp.SetSchemaUrl(semconv.SchemaURL)

		for _, profileType := range profileTypes {
			if len(toEvents.Events[profileType]) == 0 {
				// Do not append empty profiles.
				continue
			}

			isHeapAlloc := profileType.SampleType == "alloc_space"

			// For most origins this emits a single profile. Heap-alloc is
			// special: it emits a paired alloc_space (bytes) + alloc_objects
			// (count) from the same events. Both calls use the same sorted
			// key order so their sample indices line up (see sampleKeys doc).
			prof := sp.Profiles().AppendEmpty()
			if err := p.setProfile(dic, attrMgr,
				stringSet, funcSet, mappingSet, stackSet, locationSet, linkSet,
				profileType, profileKindDefault, toEvents.Events[profileType], prof,
				collectionStartTime, collectionEndTime); err != nil {
				return profiles, err
			}

			if isHeapAlloc {
				prof := sp.Profiles().AppendEmpty()
				if err := p.setProfile(dic, attrMgr,
					stringSet, funcSet, mappingSet, stackSet, locationSet, linkSet,
					profileType, profileKindHeapAllocObjects, toEvents.Events[profileType], prof,
					collectionStartTime, collectionEndTime); err != nil {
					return profiles, err
				}
			}
		}

	}

	// Append source profiles from probes (e.g. live heap inuse).
	for _, sp := range sourceProfiles {
		appendSourceProfile(profiles, dic, attrMgr, stringSet, funcSet, locationSet, mappingSet, stackSet,
			agentName, agentVersion, collectionStartTime, collectionEndTime,
			sp, processMeta)
	}

	// Populate the ProfilesDictionary tables.
	funcTable := dic.FunctionTable()
	funcTable.EnsureCapacity(len(funcSet))
	for range funcSet {
		funcTable.AppendEmpty()
	}
	for v, idx := range funcSet {
		f := funcTable.At(int(idx))
		f.SetNameStrindex(v.nameIdx)
		f.SetFilenameStrindex(v.fileNameIdx)
	}

	stringTable := dic.StringTable()
	stringTable.EnsureCapacity(len(stringSet))
	for _, val := range stringSet.ToSlice() {
		stringTable.Append(val)
	}

	return profiles, nil
}

// setProfile sets the data an OTLP profile with all collected samples up to
// this moment.
func (p *Pdata) setProfile(
	dic pprofile.ProfilesDictionary,
	attrMgr *samples.AttrTableManager,
	stringSet orderedset.OrderedSet[string],
	funcSet orderedset.OrderedSet[funcInfo],
	mappingSet orderedset.OrderedSet[libpf.FrameMapping],
	stackSet orderedset.OrderedSet[stackInfo],
	locationSet orderedset.OrderedSet[locationInfo],
	linkSet orderedset.OrderedSet[linkInfo],
	profileType *samples.TypeMetadata,
	kind profileKind,
	events samples.SampleToEvents,
	profile pprofile.Profile,
	collectionStartTime, collectionEndTime time.Time,
) error {
	if profileType.PeriodType != "" {
		profile.SetPeriod(1e9 / int64(p.samplesPerSecond))
		pt := profile.PeriodType()
		pt.SetTypeStrindex(stringSet.Add(profileType.PeriodType))
		pt.SetUnitStrindex(stringSet.Add(profileType.PeriodUnit))
	}

	st := profile.SampleType()
	if kind == profileKindHeapAllocObjects {
		st.SetTypeStrindex(stringSet.Add("alloc_objects"))
		st.SetUnitStrindex(stringSet.Add("count"))
	} else {
		st.SetTypeStrindex(stringSet.Add(profileType.SampleType))
		st.SetUnitStrindex(stringSet.Add(profileType.SampleUnit))
	}

	isHeapAlloc := profileType.SampleType == "alloc_space"

	// Heap-alloc uses a deterministic key order so that the paired
	// alloc_space and alloc_objects profiles list samples in the same
	// sequence; downstream consumers that opt into correlating them by
	// index rely on this. Other origins emit a single profile and skip
	// the sort (no performance cost on the CPU/off-CPU/probe paths).
	for _, sampleKey := range sampleKeys(events, isHeapAlloc) {
		traceInfo := events[sampleKey]
		sample := profile.Samples().AppendEmpty()

		sample.TimestampsUnixNano().FromRaw(traceInfo.Timestamps)
		if isHeapAlloc && kind == profileKindHeapAllocObjects {
			// The profiler uses sampling: only a subset of allocations
			// are observed, and for each observed allocation the eBPF
			// probe reports:
			//   weight = unbiased byte estimator (nsamples * interval)
			//   size   = raw allocation size in bytes
			//
			// To derive an equally unbiased object-count estimator we
			// compute weight/size: a sample representing `weight` bytes
			// of `size`-byte objects represents weight/size objects.
			// This is the standard convention used by tcmalloc, jemalloc,
			// and Go's pprof runtime.
			//
			// We do this division here in userspace (rather than in the
			// eBPF program) so that the raw size remains available for
			// potential future use (e.g. allocation-size histograms) and
			// so formula changes don't require an eBPF blob rebuild.
			//
			// Fall back to 1 if size is unknown/zero (malformed sampler
			// output) rather than dividing by zero.
			for i, weight := range traceInfo.Values {
				objects := int64(1)
				if i < len(traceInfo.AllocSizes) && traceInfo.AllocSizes[i] > 0 {
					objects = weight / traceInfo.AllocSizes[i]
					if objects < 1 {
						objects = 1
					}
				}
				sample.Values().Append(objects)
			}
		} else if profileType.ReportValues {
			sample.Values().Append(traceInfo.Values...)
		}

		if sampleKey.SpanID != libpf.InvalidAPMSpanID &&
			sampleKey.TraceID != libpf.InvalidAPMTraceID {
			link, ok := linkSet.AddWithCheck(linkInfo{
				traceID: sampleKey.TraceID,
				spanID:  sampleKey.SpanID,
			})
			if !ok {
				l := dic.LinkTable().AppendEmpty()
				l.SetSpanID(pcommon.SpanID(sampleKey.SpanID))
				l.SetTraceID(pcommon.TraceID(sampleKey.TraceID))

			}
			sample.SetLinkIndex(link)
		}

		stackIdx := appendFramesAsStack(traceInfo.Frames, dic, attrMgr,
			stringSet, funcSet, mappingSet, locationSet, stackSet)
		sample.SetStackIndex(stackIdx)

		for key, value := range traceInfo.Labels {
			// Once https://github.com/open-telemetry/semantic-conventions/issues/2561
			// reached an agreement, use the actual OTel SemConv attribute.
			attrMgr.AppendOptionalString(
				sample.AttributeIndices(),
				attribute.Key("process.context.label."+key.String()),
				value.String())
		}

		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ThreadNameKey, sampleKey.Comm.String())
		attrMgr.AppendInt(sample.AttributeIndices(),
			semconv.ThreadIDKey, sampleKey.TID)
		attrMgr.AppendInt(sample.AttributeIndices(),
			semconv.CPULogicalNumberKey, int64(sampleKey.CPU))

		if p.ExtraSampleAttrProd != nil {
			extra := p.ExtraSampleAttrProd.ExtraSampleAttrs(attrMgr, sampleKey.ExtraMeta)
			sample.AttributeIndices().Append(extra...)
		}
	} // End sample processing

	log.Debugf("Reporting OTLP profile with %d samples", profile.Samples().Len())

	profile.SetDurationNano(uint64(collectionEndTime.Sub(collectionStartTime).Nanoseconds()))
	profile.SetTime(pcommon.Timestamp(collectionStartTime.UnixNano()))

	return nil
}

func setResourceAttributes(attrs pcommon.Map, resource samples.ResourceKey, envVars map[libpf.String]libpf.String) {
	if resource.APMServiceName != "" {
		attrs.PutStr(string(semconv.ServiceNameKey), resource.APMServiceName)
	}
	if resource.ContainerID != libpf.NullString {
		attrs.PutStr(string(semconv.ContainerIDKey), resource.ContainerID.String())
	}

	attrs.PutInt(string(semconv.ProcessPIDKey), resource.PID)

	if resource.ExecutablePath != libpf.NullString {
		attrs.PutStr(string(semconv.ProcessExecutablePathKey), resource.ExecutablePath.String())
		_, exeName := filepath.Split(resource.ExecutablePath.String())
		attrs.PutStr(string(semconv.ProcessExecutableNameKey), exeName)
	}

	for key, value := range envVars {
		attrs.PutStr("process.environment_variable."+key.String(), value.String())
	}
}
