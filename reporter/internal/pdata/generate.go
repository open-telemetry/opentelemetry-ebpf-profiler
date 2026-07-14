// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"path/filepath"
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

// Generate generates a pdata request out of internal profiles data, to be
// exported. The collectionStartTime and collectionEndTime define the time window
// during which the profiler was actively collecting samples.
func (p *Pdata) Generate(tree samples.TraceEventsTree,
	agentName, agentVersion string,
	collectionStartTime, collectionEndTime time.Time,
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

			// Sample order is shared by the primary profile and
			// every derived profile below, so sample i of each refers to the
			// same trace. This isn't part of the OTLP spec, but in practice
			// can make it easier for OTLP consumers to recover paired samples.
			keys := make([]samples.SampleKey, 0, len(events))
			for k := range events {
				keys = append(keys, k)
			}

			// Add primary profile
			prof := sp.Profiles().AppendEmpty()
			if err := p.setProfile(dic, attrMgr,
				stringSet, funcSet, mappingSet, stackSet, locationSet, linkSet,
				profileType, nil, events, keys, prof,
				collectionStartTime, collectionEndTime); err != nil {
				return profiles, err
			}

			// Add any derived profiles
			for i := range profileType.DerivedProfiles {
				prof := sp.Profiles().AppendEmpty()
				if err := p.setProfile(dic, attrMgr,
					stringSet, funcSet, mappingSet, stackSet, locationSet, linkSet,
					profileType, &profileType.DerivedProfiles[i], events, keys, prof,
					collectionStartTime, collectionEndTime); err != nil {
					return profiles, err
				}
			}
		}
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
	derived *samples.DerivedProfile,
	events samples.SampleToEvents,
	keys []samples.SampleKey,
	profile pprofile.Profile,
	collectionStartTime, collectionEndTime time.Time,
) error {
	if profileType.PeriodType != "" {
		profile.SetPeriod(1e9 / int64(p.samplesPerSecond))
		pt := profile.PeriodType()
		pt.SetTypeStrindex(stringSet.Add(profileType.PeriodType))
		pt.SetUnitStrindex(stringSet.Add(profileType.PeriodUnit))
	}

	// Take the derived sample type & unit if we're working with a derived profile,
	// otherwise the default.
	sampleType, sampleUnit := profileType.SampleType, profileType.SampleUnit
	if derived != nil {
		sampleType, sampleUnit = derived.SampleType, derived.SampleUnit
	}
	st := profile.SampleType()
	st.SetTypeStrindex(stringSet.Add(sampleType))
	st.SetUnitStrindex(stringSet.Add(sampleUnit))

	for _, sampleKey := range keys {
		traceInfo := events[sampleKey]
		sample := profile.Samples().AppendEmpty()

		sample.TimestampsUnixNano().FromRaw(traceInfo.Timestamps)

		// If we've been given a derived profile, emit for that
		if derived != nil {
			// One derived value per primary value, so the result stays
			// index-aligned with Timestamps. A missing extra is passed as
			// the zero value and the probe's callback decides what that means.
			for i, v := range traceInfo.Values {
				var extra [2]uint64
				if i < len(traceInfo.ValuesExtra) {
					extra = traceInfo.ValuesExtra[i]
				}
				sample.Values().Append(derived.Value(v, extra))
			}
		} else if profileType.ReportValues { // ... if we've not, emit for the main profile, if asked
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
		if !profileType.OmitThreadContext {
			attrMgr.AppendInt(sample.AttributeIndices(),
				semconv.ThreadIDKey, sampleKey.TID)
			attrMgr.AppendInt(sample.AttributeIndices(),
				semconv.CPULogicalNumberKey, int64(sampleKey.CPU))
		}

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
