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
	"go.opentelemetry.io/ebpf-profiler/support"
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

	// Find oldest sample timestamp across all containers to handle buffered samples.
	adjustedStartTime := collectionStartTime
	for _, containerEvents := range tree {
		for _, originEvents := range containerEvents {
			for _, traceEvents := range originEvents {
				for _, ts := range traceEvents.Timestamps {
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

	// By specification, the first element should be empty.
	stringSet.Add("")
	funcSet.Add(funcInfo{})
	mappingSet.Add(libpf.FrameMapping{})
	stackSet.Add(stackInfo{})
	locationSet.Add(locationInfo{})

	dic.LinkTable().AppendEmpty()
	dic.MappingTable().AppendEmpty()
	dic.StackTable().AppendEmpty()
	dic.AttributeTable().AppendEmpty()
	dic.LocationTable().AppendEmpty()

	attrMgr := samples.NewAttrTableManager(stringSet, dic.AttributeTable())

	for containerID, originToEvents := range tree {
		if len(originToEvents) == 0 {
			continue
		}

		rp := profiles.ResourceProfiles().AppendEmpty()
		rp.Resource().Attributes().PutStr(string(semconv.ContainerIDKey),
			containerID.String())
		rp.SetSchemaUrl(semconv.SchemaURL)

		sp := rp.ScopeProfiles().AppendEmpty()
		sp.Scope().SetName(agentName)
		sp.Scope().SetVersion(agentVersion)
		sp.SetSchemaUrl(semconv.SchemaURL)

		for _, origin := range []libpf.Origin{
			support.TraceOriginSampling,
			support.TraceOriginOffCPU,
			support.TraceOriginProbe,
		} {
			if len(originToEvents[origin]) == 0 {
				// Do not append empty profiles.
				continue
			}

			prof := sp.Profiles().AppendEmpty()
			if err := p.setProfile(dic,
				attrMgr, stringSet, funcSet, mappingSet, stackSet, locationSet,
				origin, originToEvents[origin], prof,
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
	origin libpf.Origin,
	events map[samples.TraceAndMetaKey]*samples.TraceEvents,
	profile pprofile.Profile,
	collectionStartTime, collectionEndTime time.Time,
) error {
	st := profile.SampleType()
	switch origin {
	case support.TraceOriginSampling:
		profile.SetPeriod(1e9 / int64(p.samplesPerSecond))
		pt := profile.PeriodType()
		pt.SetTypeStrindex(stringSet.Add("cpu"))
		pt.SetUnitStrindex(stringSet.Add("nanoseconds"))

		st.SetTypeStrindex(stringSet.Add("samples"))
		st.SetUnitStrindex(stringSet.Add("count"))
	case support.TraceOriginOffCPU:
		st.SetTypeStrindex(stringSet.Add("off_cpu"))
		st.SetUnitStrindex(stringSet.Add("nanoseconds"))
	case support.TraceOriginProbe:
		st.SetTypeStrindex(stringSet.Add("events"))
		st.SetUnitStrindex(stringSet.Add("count"))
	default:
		// Should never happen
		return fmt.Errorf("generating profile for unsupported origin %d", origin)
	}

	for traceKey, traceInfo := range events {
		sample := profile.Samples().AppendEmpty()

		sample.TimestampsUnixNano().FromRaw(traceInfo.Timestamps)
		if origin == support.TraceOriginOffCPU {
			sample.Values().Append(traceInfo.OffTimes...)
		}

		locationIndices := make([]int32, 0, len(traceInfo.Frames))
		// Walk every frame of the trace.
		for _, uniqueFrame := range traceInfo.Frames {
			frame := uniqueFrame.Value()
			locInfo := locationInfo{
				address:   uint64(frame.AddressOrLineno),
				frameType: frame.Type.String(),
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

				// Once SemConv and its Go package is released with the new
				// semantic convention for build_id, replace these hard coded
				// strings.
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
					semconv.ProfileFrameTypeKey, locInfo.frameType)
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

		exeName := ""
		if traceKey.ExecutablePath != libpf.NullString {
			_, exeName = filepath.Split(traceKey.ExecutablePath.String())
		}

		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ThreadNameKey, traceKey.Comm.String())

		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ProcessExecutableNameKey, exeName)
		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ProcessExecutablePathKey, traceKey.ExecutablePath.String())

		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ServiceNameKey, traceKey.ApmServiceName)
		attrMgr.AppendInt(sample.AttributeIndices(),
			semconv.ProcessPIDKey, traceKey.Pid)
		attrMgr.AppendInt(sample.AttributeIndices(),
			semconv.ThreadIDKey, traceKey.Tid)
		attrMgr.AppendInt(sample.AttributeIndices(),
			semconv.CPULogicalNumberKey, int64(traceKey.CPU))

		for key, value := range traceInfo.EnvVars {
			env := semconv.ProcessEnvironmentVariable(key.String(), value.String())
			attrMgr.AppendOptionalString(
				sample.AttributeIndices(),
				env.Key, env.Value.AsString())
		}
		for key, value := range traceInfo.Labels {
			// Once https://github.com/open-telemetry/semantic-conventions/issues/2561
			// reached an agreement, use the actual OTel SemConv attribute.
			attrMgr.AppendOptionalString(
				sample.AttributeIndices(),
				attribute.Key("process.context.label."+key.String()),
				value.String())
		}

		if p.ExtraSampleAttrProd != nil {
			extra := p.ExtraSampleAttrProd.ExtraSampleAttrs(attrMgr, traceKey.ExtraMeta)
			sample.AttributeIndices().Append(extra...)
		}
	} // End sample processing

	log.Debugf("Reporting OTLP profile with %d samples", profile.Samples().Len())

	profile.SetDurationNano(uint64(collectionEndTime.Sub(collectionStartTime).Nanoseconds()))
	profile.SetTime(pcommon.Timestamp(collectionStartTime.UnixNano()))

	return nil
}
