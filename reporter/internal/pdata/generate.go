// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"fmt"
	"path/filepath"
	"slices"
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

// Used as a key in an ordered set, in order to deduplicate Locations.
type locationInfo struct {
	address       uint64
	mappingIndex  int32
	frameType     string
	hasLine       bool
	lineNumber    int64
	functionIndex int32
}

// Generate generates a pdata request out of internal profiles data, to be
// exported.
func (p *Pdata) Generate(tree samples.TraceEventsTree,
	agentName, agentVersion string) (pprofile.Profiles, error) {
	profiles := pprofile.NewProfiles()
	dic := profiles.ProfilesDictionary()

	// Temporary helpers that will build the various tables in ProfilesDictionary.
	stringSet := libpf.OrderedSet[string]{}
	funcSet := libpf.OrderedSet[samples.FuncInfo]{}
	mappingSet := libpf.OrderedSet[libpf.FileID]{}
	locationSet := libpf.OrderedSet[locationInfo]{}

	// By specification, the first element should be empty.
	stringSet.Add("")
	funcSet.Add(samples.FuncInfo{Name: "", FileName: ""})

	for containerID, originToEvents := range tree {
		if len(originToEvents) == 0 {
			continue
		}

		rp := profiles.ResourceProfiles().AppendEmpty()
		rp.Resource().Attributes().PutStr(string(semconv.ContainerIDKey),
			string(containerID))

		sp := rp.ScopeProfiles().AppendEmpty()
		sp.Scope().SetName(agentName)
		sp.Scope().SetVersion(agentVersion)

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
		f := funcTable.At(idx)
		f.SetNameStrindex(int32(stringSet.Add(v.Name)))
		f.SetFilenameStrindex(int32(stringSet.Add(v.FileName)))
	}

	for _, val := range stringSet.ToSlice() {
		dic.StringTable().Append(val)
	}

	return profiles, nil
}

// setProfile sets the data an OTLP profile with all collected samples up to
// this moment.
func (p *Pdata) setProfile(
	dic pprofile.ProfilesDictionary,
	stringSet libpf.OrderedSet[string],
	funcSet libpf.OrderedSet[samples.FuncInfo],
	mappingSet libpf.OrderedSet[libpf.FileID],
	locationSet libpf.OrderedSet[locationInfo],
	origin libpf.Origin,
	events map[samples.TraceAndMetaKey]*samples.TraceEvents,
	profile pprofile.Profile,
) error {
	st := profile.SampleType().AppendEmpty()
	switch origin {
	case support.TraceOriginSampling:
		profile.SetPeriod(1e9 / int64(p.samplesPerSecond))
		pt := profile.PeriodType()
		pt.SetTypeStrindex(int32(stringSet.Add("cpu")))
		pt.SetUnitStrindex(int32(stringSet.Add("nanoseconds")))

		st.SetTypeStrindex(int32(stringSet.Add("samples")))
		st.SetUnitStrindex(int32(stringSet.Add("count")))
	case support.TraceOriginOffCPU:
		st.SetTypeStrindex(int32(stringSet.Add("events")))
		st.SetUnitStrindex(int32(stringSet.Add("nanoseconds")))
	default:
		// Should never happen
		return fmt.Errorf("generating profile for unsupported origin %d", origin)
	}

	attrMgr := samples.NewAttrTableManager(dic.AttributeTable())

	locationIndex := int32(profile.LocationIndices().Len())
	var startTS, endTS pcommon.Timestamp
	for traceKey, traceInfo := range events {
		sample := profile.Sample().AppendEmpty()
		sample.SetLocationsStartIndex(locationIndex)

		slices.Sort(traceInfo.Timestamps)
		startTS = pcommon.Timestamp(traceInfo.Timestamps[0])
		endTS = pcommon.Timestamp(traceInfo.Timestamps[len(traceInfo.Timestamps)-1])
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
					mapping.SetFilenameStrindex(int32(stringSet.Add(fileName)))

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
				locInfo.mappingIndex = int32(locationMappingIndex)
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
					fi := samples.FuncInfo{
						Name:     si.FunctionName,
						FileName: si.FilePath,
					}
					locInfo.functionIndex = int32(funcSet.Add(fi))
				} else {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					// To differentiate this case from the case where no information about
					// the file ID is available at all, we use a different name for reported
					// function.
					fi := samples.FuncInfo{
						Name:     "UNRESOLVED",
						FileName: frameKind.String(),
					}
					locInfo.functionIndex = int32(funcSet.Add(fi))
				}

				idx, exists := mappingSet.AddWithCheck(traceInfo.Files[i])
				locInfo.mappingIndex = int32(idx)
				if !exists {
					// To be compliant with the protocol, generate a dummy mapping entry.
					mapping := dic.MappingTable().AppendEmpty()
					mapping.SetFilenameStrindex(int32(stringSet.Add("")))
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
			profile.LocationIndices().Append(int32(idx))
		} // End per-frame processing

		exeName := traceKey.ExecutablePath
		if exeName != "" {
			_, exeName = filepath.Split(exeName)
		}

		attrMgr.AppendOptionalString(sample.AttributeIndices(),
			semconv.ContainerIDKey, traceKey.ContainerID)
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

	profile.SetDuration(endTS - startTS)
	profile.SetStartTime(startTS)

	return nil
}
