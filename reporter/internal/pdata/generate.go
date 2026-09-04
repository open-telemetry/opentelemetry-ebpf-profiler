// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"cmp"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/otel/attribute"

	"go.opentelemetry.io/ebpf-profiler/internal/log"

	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

const (
	ExecutableCacheLifetime = 1 * time.Hour
)

// hasAllocSizes reports whether any event in the set carries per-event
// allocation sizes. When true, the reporter emits a paired object-count
// profile alongside the primary byte-weighted profile.
//
// Ideally probes would control their own OTLP output rather than the
// reporter inferring intent from the data shape. Until the Probe API
// supports that (e.g. a probe-supplied transform from accumulated events
// to OTLP profiles), we use the structural presence of AllocSizes as
// the signal.
func hasAllocSizes(events samples.SampleToEvents) bool {
	for _, ev := range events {
		if len(ev.AllocSizes) > 0 {
			return true
		}
	}
	return false
}

// profileKind is a sub-profile discriminator used when a single origin
// produces more than one OTLP Profile message from the same event set.
// For example, heap-alloc events that carry AllocSizes emit both a
// byte-weighted profile and an object-count profile; the kind tells
// setProfile which value-type semantics to apply. Origins that emit
// only one profile use profileKindDefault.
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
	// ExtraMeta is `any` but constrained to comparable types (SampleKey is a
	// map key). Type-assert the common case (string) for a cheap comparison;
	// fall back to Sprint for exotic types.
	as, aOK := a.ExtraMeta.(string)
	bs, bOK := b.ExtraMeta.(string)
	if aOK && bOK {
		return cmp.Compare(as, bs)
	}
	return cmp.Compare(fmt.Sprint(a.ExtraMeta), fmt.Sprint(b.ExtraMeta))
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

	for resource, toEvents := range tree {
		if len(toEvents.Events) == 0 {
			continue
		}

		rp := profiles.ResourceProfiles().AppendEmpty()
		setResourceAttributes(rp.Resource().Attributes(), resource, toEvents.EnvVars,
			toEvents.ResourceAttrs)
		rp.SetSchemaUrl(semconv.SchemaURL)

		sp := rp.ScopeProfiles().AppendEmpty()
		sp.Scope().SetName(agentName)
		sp.Scope().SetVersion(agentVersion)
		sp.SetSchemaUrl(semconv.SchemaURL)

		for profileType, events := range toEvents.Events {
			if len(events) == 0 {
				// Do not append empty profiles.
				continue
			}

			pairedObjects := hasAllocSizes(events)

			// For most origins this emits a single profile. When events
			// carry per-allocation sizes, a paired object-count profile
			// is emitted alongside the primary byte-weighted one. Both
			// use the same sorted key order so their sample indices line
			// up (see sampleKeys doc).
			prof := sp.Profiles().AppendEmpty()
			if err := p.setProfile(dic, attrMgr,
				stringSet, funcSet, mappingSet, stackSet, locationSet, linkSet,
				profileType, profileKindDefault, events, prof,
				collectionStartTime, collectionEndTime); err != nil {
				return profiles, err
			}

			if pairedObjects {
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

	pairedObjects := hasAllocSizes(events)

	// When a paired object-count profile is emitted, both profiles must
	// list samples in the same deterministic order so downstream consumers
	// can correlate them by index. Other origins emit a single profile
	// and skip the sort (no cost on CPU/off-CPU/probe paths).
	for _, sampleKey := range sampleKeys(events, pairedObjects) {
		traceInfo := events[sampleKey]
		sample := profile.Samples().AppendEmpty()

		sample.TimestampsUnixNano().FromRaw(traceInfo.Timestamps)
		if pairedObjects && kind == profileKindHeapAllocObjects {
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
					objects = max(weight/traceInfo.AllocSizes[i], 1)
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

func setResourceAttributes(dst pcommon.Map, resourceKey samples.ResourceKey,
	envVars map[libpf.String]libpf.String, resourceAttrs attribute.Set) {
	// service.name, container.id, process.pid, process.executable.{path,name}
	dst.EnsureCapacity(resourceAttrs.Len() + len(envVars) + 5)
	for iter := resourceAttrs.Iter(); iter.Next(); {
		kv := iter.Attribute()
		setAttributeValue(dst.PutEmpty(string(kv.Key)), kv.Value)
	}
	if resourceKey.APMServiceName != "" {
		dst.PutStr(string(semconv.ServiceNameKey), resourceKey.APMServiceName)
	}
	if resourceKey.ContainerID != libpf.NullString {
		dst.PutStr(string(semconv.ContainerIDKey), resourceKey.ContainerID.String())
	}

	dst.PutInt(string(semconv.ProcessPIDKey), resourceKey.PID)

	if resourceKey.ExecutablePath != libpf.NullString {
		dst.PutStr(string(semconv.ProcessExecutablePathKey), resourceKey.ExecutablePath.String())
		_, exeName := filepath.Split(resourceKey.ExecutablePath.String())
		dst.PutStr(string(semconv.ProcessExecutableNameKey), exeName)
	}

	for key, value := range envVars {
		dst.PutStr("process.environment_variable."+key.String(), value.String())
	}
}

// setAttributeValue writes src into dst. dst is already inserted in its
// container, so a case that writes nothing yields an empty pcommon value.
func setAttributeValue(dst pcommon.Value, src attribute.Value) {
	switch src.Type() {
	case attribute.BOOL:
		dst.SetBool(src.AsBool())
	case attribute.INT64:
		dst.SetInt(src.AsInt64())
	case attribute.FLOAT64:
		dst.SetDouble(src.AsFloat64())
	case attribute.STRING:
		dst.SetStr(src.AsString())
	case attribute.BYTESLICE:
		dst.SetEmptyBytes().FromRaw(src.AsByteSlice())
	case attribute.BOOLSLICE:
		setSliceValue(dst, src.AsBoolSlice(), pcommon.Value.SetBool)
	case attribute.INT64SLICE:
		setSliceValue(dst, src.AsInt64Slice(), pcommon.Value.SetInt)
	case attribute.FLOAT64SLICE:
		setSliceValue(dst, src.AsFloat64Slice(), pcommon.Value.SetDouble)
	case attribute.STRINGSLICE:
		setSliceValue(dst, src.AsStringSlice(), pcommon.Value.SetStr)
	case attribute.SLICE:
		setSliceValue(dst, src.AsSlice(), setAttributeValue)
	case attribute.MAP:
		kvs := src.AsMap()
		m := dst.SetEmptyMap()
		m.EnsureCapacity(len(kvs))
		for _, kv := range kvs {
			setAttributeValue(m.PutEmpty(string(kv.Key)), kv.Value)
		}
	case attribute.EMPTY:
		// A published empty value, and dst already is one.
	default:
		// Reachable only if otel adds an attribute.Type.
		log.Warnf("setAttributeValue: no pcommon representation for %s, "+
			"emitting empty", src.Type())
	}
}

func setSliceValue[T any](dst pcommon.Value, values []T, set func(pcommon.Value, T)) {
	sl := dst.SetEmptySlice()
	sl.EnsureCapacity(len(values))
	for _, v := range values {
		set(sl.AppendEmpty(), v)
	}
}
