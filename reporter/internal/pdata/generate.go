// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"fmt"
	"math"
	"path/filepath"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/otel/attribute"

	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	ExecutableCacheLifetime = 1 * time.Hour
	FramesCacheLifetime     = 1 * time.Hour
	FrameMapLifetime        = 1 * time.Hour
)

// Generate generates a pdata request out of internal profiles data, to be
// exported.
func (p *Pdata) Generate(tree samples.TraceEventsTree,
	agentName, agentVersion string) (pprofile.Profiles, error) {
	profiles := pprofile.NewProfiles()
	dic := profiles.ProfilesDictionary()

	// Temporary helpers that will build the various tables in ProfilesDictionary.
	stringSet := make(OrderedSet[string], 64)
	funcSet := make(OrderedSet[funcInfo], 64)
	mappingSet := make(OrderedSet[libpf.FileID], 64)
	locationSet := make(OrderedSet[locationInfo], 64)

	// By specification, the first element should be empty.
	stringSet.Add("")
	funcSet.Add(funcInfo{nameIdx: stringSet.Add(""), fileNameIdx: stringSet.Add("")})

	for containerID, originToEvents := range tree {
		if len(originToEvents) == 0 {
			continue
		}

		rp := profiles.ResourceProfiles().AppendEmpty()
		rp.Resource().Attributes().PutStr(string(semconv.ContainerIDKey),
			string(containerID))
		rp.SetSchemaUrl(semconv.SchemaURL)

		sp := rp.ScopeProfiles().AppendEmpty()
		sp.Scope().SetName(agentName)
		sp.Scope().SetVersion(agentVersion)
		sp.SetSchemaUrl(semconv.SchemaURL)

		for _, origin := range []libpf.Origin{
			support.TraceOriginSampling,
			support.TraceOriginOffCPU,
		} {
			if len(originToEvents[origin]) == 0 {
				// Do not append empty profiles.
				continue
			}

			prof := sp.Profiles().AppendEmpty()
			if err := p.setProfile(dic,
				stringSet, funcSet, mappingSet, locationSet,
				origin, originToEvents[origin], prof); err != nil {
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
	stringSet OrderedSet[string],
	funcSet OrderedSet[funcInfo],
	mappingSet OrderedSet[libpf.FileID],
	locationSet OrderedSet[locationInfo],
	origin libpf.Origin,
	events map[samples.TraceAndMetaKey]*samples.TraceEvents,
	profile pprofile.Profile,
) error {
	st := profile.SampleType().AppendEmpty()
	switch origin {
	case support.TraceOriginSampling:
		profile.SetPeriod(1e9 / int64(p.samplesPerSecond))
		pt := profile.PeriodType()
		pt.SetTypeStrindex(stringSet.Add("cpu"))
		pt.SetUnitStrindex(stringSet.Add("nanoseconds"))

		st.SetTypeStrindex(stringSet.Add("samples"))
		st.SetUnitStrindex(stringSet.Add("count"))
	case support.TraceOriginOffCPU:
		st.SetTypeStrindex(stringSet.Add("events"))
		st.SetUnitStrindex(stringSet.Add("nanoseconds"))
	default:
		// Should never happen
		return fmt.Errorf("generating profile for unsupported origin %d", origin)
	}

	attrMgr := samples.NewAttrTableManager(dic.AttributeTable())

	locationIndex := int32(profile.LocationIndices().Len())
	startTS, endTS := uint64(math.MaxUint64), uint64(0)
	for traceKey, traceInfo := range events {
		sample := profile.Sample().AppendEmpty()
		sample.SetLocationsStartIndex(locationIndex)

		for _, ts := range traceInfo.Timestamps {
			startTS = min(startTS, ts)
			endTS = max(endTS, ts)
		}
		sample.TimestampsUnixNano().FromRaw(traceInfo.Timestamps)

		switch origin {
		case support.TraceOriginSampling:
			sample.Value().Append(1)
		case support.TraceOriginOffCPU:
			sample.Value().Append(traceInfo.OffTimes...)
		}

		// Walk every frame of the trace.
		for i := range traceInfo.FrameTypes {
			locInfo := locationInfo{
				address:   uint64(traceInfo.Linenos[i]),
				frameType: traceInfo.FrameTypes[i].String(),
			}
			switch frameKind := traceInfo.FrameTypes[i]; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.
				locationMappingIndex, exists := mappingSet.AddWithCheck(traceInfo.Files[i])
				if !exists {
					ei, exists := p.Executables.GetAndRefresh(traceInfo.Files[i],
						ExecutableCacheLifetime)
					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					fileName := "UNKNOWN"
					if exists {
						fileName = ei.FileName
					}

					mapping := dic.MappingTable().AppendEmpty()
					mapping.SetMemoryStart(uint64(traceInfo.MappingStarts[i]))
					mapping.SetMemoryLimit(uint64(traceInfo.MappingEnds[i]))
					mapping.SetFileOffset(traceInfo.MappingFileOffsets[i])
					mapping.SetFilenameStrindex(stringSet.Add(fileName))

					// Once SemConv and its Go package is released with the new
					// semantic convention for build_id, replace these hard coded
					// strings.
					attrMgr.AppendOptionalString(mapping.AttributeIndices(),
						semconv.ProcessExecutableBuildIDGNUKey,
						ei.GnuBuildID)
					attrMgr.AppendOptionalString(mapping.AttributeIndices(),
						semconv.ProcessExecutableBuildIDHtlhashKey,
						traceInfo.Files[i].StringNoQuotes())
				}
				locInfo.mappingIndex = locationMappingIndex
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originated from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as a Line message
				locInfo.hasLine = true
				if si, exists := p.Frames.GetAndRefresh(
					libpf.NewFrameID(traceInfo.Files[i], traceInfo.Linenos[i]),
					FramesCacheLifetime); exists {
					locInfo.lineNumber = int64(si.LineNumber)
					fi := funcInfo{
						nameIdx:     stringSet.Add(si.FunctionName.String()),
						fileNameIdx: stringSet.Add(si.FilePath.String()),
					}
					locInfo.functionIndex = funcSet.Add(fi)
				} else {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					// To differentiate this case from the case where no information about
					// the file ID is available at all, we use a different name for reported
					// function.
					fi := funcInfo{
						nameIdx:     stringSet.Add("UNRESOLVED"),
						fileNameIdx: stringSet.Add(frameKind.String()),
					}
					locInfo.functionIndex = funcSet.Add(fi)
				}

				idx, exists := mappingSet.AddWithCheck(traceInfo.Files[i])
				locInfo.mappingIndex = idx
				if !exists {
					// To be compliant with the protocol, generate a dummy mapping entry.
					mapping := dic.MappingTable().AppendEmpty()
					mapping.SetFilenameStrindex(stringSet.Add(""))
					attrMgr.AppendOptionalString(mapping.AttributeIndices(),
						semconv.ProcessExecutableBuildIDHtlhashKey,
						traceInfo.Files[i].StringNoQuotes())
				}
			} // End frame type switch

			idx, exists := locationSet.AddWithCheck(locInfo)
			if !exists {
				// Add a new Location to the dictionary
				loc := dic.LocationTable().AppendEmpty()
				loc.SetAddress(locInfo.address)
				loc.SetMappingIndex(locInfo.mappingIndex)
				if locInfo.hasLine {
					line := loc.Line().AppendEmpty()
					line.SetLine(locInfo.lineNumber)
					line.SetFunctionIndex(locInfo.functionIndex)
				}
				attrMgr.AppendOptionalString(loc.AttributeIndices(),
					semconv.ProfileFrameTypeKey, locInfo.frameType)
			}
			profile.LocationIndices().Append(idx)
		} // End per-frame processing

		exeName := traceKey.ExecutablePath
		if exeName != "" {
			_, exeName = filepath.Split(exeName)
		}

		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ThreadNameKey, traceKey.Comm)

		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ProcessExecutableNameKey, exeName)
		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ProcessExecutablePathKey, traceKey.ExecutablePath)

		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ServiceNameKey, traceKey.ApmServiceName)
		attrMgr.AppendInt(sample.AttributeIndices(),
			semconv.ProcessPIDKey, traceKey.Pid)
		attrMgr.AppendInt(sample.AttributeIndices(),
			semconv.ThreadIDKey, traceKey.Tid)

		for key, value := range traceInfo.EnvVars {
			attrMgr.AppendOptionalString(
				sample.AttributeIndices(),
				attribute.Key("process.environment_variable."+key),
				value)
		}

		if p.ExtraSampleAttrProd != nil {
			extra := p.ExtraSampleAttrProd.ExtraSampleAttrs(attrMgr, traceKey.ExtraMeta)
			sample.AttributeIndices().Append(extra...)
		}

		sample.SetLocationsLength(int32(len(traceInfo.FrameTypes)))
		locationIndex += sample.LocationsLength()
	} // End sample processing

	log.Debugf("Reporting OTLP profile with %d samples", profile.Sample().Len())

	profile.SetDuration(pcommon.Timestamp(endTS - startTS))
	profile.SetStartTime(pcommon.Timestamp(startTS))

	return nil
}
