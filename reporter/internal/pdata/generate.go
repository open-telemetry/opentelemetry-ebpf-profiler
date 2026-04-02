// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"fmt"
	"path/filepath"
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
		setResourceAttributes(rp.Resource().Attributes(), resource, toEvents.EnvVars)
		rp.SetSchemaUrl(semconv.SchemaURL)

		sp := rp.ScopeProfiles().AppendEmpty()
		sp.Scope().SetName(agentName)
		sp.Scope().SetVersion(agentVersion)
		sp.SetSchemaUrl(semconv.SchemaURL)

		for origin := range p.probeMetadata {
			if len(toEvents.Events[origin]) == 0 {
				// Do not append empty profiles.
				continue
			}

			prof := sp.Profiles().AppendEmpty()
			if err := p.setProfile(dic, attrMgr,
				stringSet, funcSet, mappingSet, stackSet, locationSet, linkSet,
				origin, toEvents.Events[origin], prof,
				collectionStartTime, collectionEndTime); err != nil {
				return profiles, err
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
	origin libpf.Origin,
	events samples.SampleToEvents,
	profile pprofile.Profile,
	collectionStartTime, collectionEndTime time.Time,
) error {
	st := profile.SampleType()
	meta, ok := p.probeMetadata[origin]
	if !ok {
		return fmt.Errorf("generating profile for unsupported origin %d", origin)
	}
	if meta.Period > 0 {
		profile.SetPeriod(meta.Period)
	}
	if meta.PeriodType != "" {
		pt := profile.PeriodType()
		pt.SetTypeStrindex(stringSet.Add(meta.PeriodType))
		pt.SetUnitStrindex(stringSet.Add(meta.PeriodUnit))
	}
	st.SetTypeStrindex(stringSet.Add(meta.Typ))
	st.SetUnitStrindex(stringSet.Add(meta.Unit))

	for sampleKey, traceInfo := range events {
		sample := profile.Samples().AppendEmpty()

		sample.TimestampsUnixNano().FromRaw(traceInfo.Timestamps)
		probeMeta, ok := p.probeMetadata[origin]
		if ok && probeMeta.ReportValues {
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

		locationIndices := make([]int32, 0, len(traceInfo.Frames))
		// Walk every frame of the trace.
		for _, uniqueFrame := range traceInfo.Frames {
			frame := uniqueFrame.Value()
			locInfo := locationInfo{
				address:   uint64(frame.AddressOrLineno),
				frameType: frame.Type,
			}

			index, ok := mappingSet.AddWithCheck(frame.Mapping)
			if !ok {
				m := frame.Mapping.Value()
				mf := m.File.Value()

				mapping := dic.MappingTable().AppendEmpty()
				mapping.SetMemoryStart(uint64(m.Start))
				mapping.SetMemoryLimit(uint64(m.End))
				mapping.SetFileOffset(m.FileOffset)
				mapping.SetFilenameStrindex(stringSet.Add(mf.FileName.String()))

				attrMgr.AppendOptionalString(mapping.AttributeIndices(),
					semconv.ProcessExecutableBuildIDGNUKey,
					mf.GnuBuildID)
				attrMgr.AppendOptionalString(mapping.AttributeIndices(),
					semconv.ProcessExecutableBuildIDGoKey,
					mf.GoBuildID)
				attrMgr.AppendOptionalString(mapping.AttributeIndices(),
					semconv.ProcessExecutableBuildIDHtlhashKey,
					mf.FileID.StringNoQuotes())
			}
			locInfo.mappingIndex = index

			if frame.FunctionName != libpf.NullString || frame.SourceFile != libpf.NullString {
				// Store interpreted frame information as a Line message
				locInfo.hasLine = true
				locInfo.lineNumber = int64(frame.SourceLine)
				locInfo.columnNumber = int64(frame.SourceColumn)
				fi := funcInfo{
					nameIdx:     stringSet.Add(frame.FunctionName.String()),
					fileNameIdx: stringSet.Add(frame.SourceFile.String()),
				}
				locInfo.functionIndex = funcSet.Add(fi)
			}

			idx, exists := locationSet.AddWithCheck(locInfo)
			if !exists {
				// Add a new Location to the dictionary
				loc := dic.LocationTable().AppendEmpty()
				loc.SetAddress(locInfo.address)
				loc.SetMappingIndex(locInfo.mappingIndex)
				if locInfo.hasLine {
					line := loc.Lines().AppendEmpty()
					line.SetLine(locInfo.lineNumber)
					line.SetColumn(locInfo.columnNumber)
					line.SetFunctionIndex(locInfo.functionIndex)
				}
				attrMgr.AppendOptionalString(loc.AttributeIndices(),
					semconv.ProfileFrameTypeKey, locInfo.frameType.String())
			}
			locationIndices = append(locationIndices, idx)
		} // End per-frame processing

		stackIdx, exists := stackSet.AddWithCheck(stackInfo{
			locationIndicesHash: hashLocationIndices(locationIndices),
		})
		if !exists {
			// Add a new Stack to the dictionary
			stack := dic.StackTable().AppendEmpty()
			for _, locIdx := range locationIndices {
				stack.LocationIndices().Append(locIdx)
			}
		}
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
