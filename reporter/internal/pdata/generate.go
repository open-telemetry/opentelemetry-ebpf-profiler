// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"crypto/rand"
	"path/filepath"
	"slices"
	"time"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/otel/attribute"

	semconv "go.opentelemetry.io/otel/semconv/v1.30.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

const (
	ExecutableCacheLifetime = 1 * time.Hour
	FramesCacheLifetime     = 1 * time.Hour
)

// Generate generates a pdata request out of internal profiles data, to be
// exported.
func (p *Pdata) Generate(events map[libpf.Origin]samples.KeyToEventMapping) pprofile.Profiles {
	profiles := pprofile.NewProfiles()
	rp := profiles.ResourceProfiles().AppendEmpty()
	sp := rp.ScopeProfiles().AppendEmpty()
	for _, origin := range []libpf.Origin{support.TraceOriginSampling,
		support.TraceOriginOffCPU} {
		if len(events[origin]) == 0 {
			// Do not append empty profiles, if there
			// is not profiling data for this origin.
			continue
		}
		prof := sp.Profiles().AppendEmpty()
		prof.SetProfileID(pprofile.ProfileID(mkProfileID()))
		p.setProfile(origin, events[origin], prof)
	}
	return profiles
}

// mkProfileID creates a random profile ID.
func mkProfileID() []byte {
	profileID := make([]byte, 16)
	_, err := rand.Read(profileID)
	if err != nil {
		return []byte("opentelemetry-ebpf-profiler")
	}
	return profileID
}

// setProfile sets the data an OTLP profile with all collected samples up to
// this moment.
func (p *Pdata) setProfile(
	origin libpf.Origin,
	events map[samples.TraceAndMetaKey]*samples.TraceEvents,
	profile pprofile.Profile,
) {
	// stringMap is a temporary helper that will build the StringTable.
	// By specification, the first element should be empty.
	stringMap := make(map[string]int32)
	stringMap[""] = 0

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[samples.FuncInfo]int32)
	funcMap[samples.FuncInfo{Name: "", FileName: ""}] = 0

	st := profile.SampleType().AppendEmpty()
	switch origin {
	case support.TraceOriginSampling:
		st.SetTypeStrindex(getStringMapIndex(stringMap, "samples"))
		st.SetUnitStrindex(getStringMapIndex(stringMap, "count"))

		pt := profile.PeriodType()
		pt.SetTypeStrindex(getStringMapIndex(stringMap, "cpu"))
		pt.SetUnitStrindex(getStringMapIndex(stringMap, "nanoseconds"))

		profile.SetPeriod(1e9 / int64(p.samplesPerSecond))
	case support.TraceOriginOffCPU:
		st.SetTypeStrindex(getStringMapIndex(stringMap, "events"))
		st.SetUnitStrindex(getStringMapIndex(stringMap, "nanoseconds"))
	default:
		log.Errorf("Generating profile for unsupported origin %d", origin)
		return
	}

	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]int32)

	attrMgr := samples.NewAttrTableManager(profile.AttributeTable())
	var locationIndex int32
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
			loc := profile.LocationTable().AppendEmpty()
			loc.SetAddress(uint64(traceInfo.Linenos[i]))
			attrMgr.AppendOptionalString(loc.AttributeIndices(),
				semconv.ProfileFrameTypeKey, traceInfo.FrameTypes[i].String())

			switch frameKind := traceInfo.FrameTypes[i]; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.

				var locationMappingIndex int32
				if tmpMappingIndex, exists := fileIDtoMapping[traceInfo.Files[i]]; exists {
					locationMappingIndex = tmpMappingIndex
				} else {
					idx := int32(len(fileIDtoMapping))
					fileIDtoMapping[traceInfo.Files[i]] = idx
					locationMappingIndex = idx

					ei, exists := p.Executables.GetAndRefresh(traceInfo.Files[i],
						ExecutableCacheLifetime)

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = "UNKNOWN"
					if exists {
						fileName = ei.FileName
					}

					mapping := profile.MappingTable().AppendEmpty()
					mapping.SetMemoryStart(uint64(traceInfo.MappingStarts[i]))
					mapping.SetMemoryLimit(uint64(traceInfo.MappingEnds[i]))
					mapping.SetFileOffset(traceInfo.MappingFileOffsets[i])
					mapping.SetFilenameStrindex(getStringMapIndex(stringMap, fileName))

					// Once SemConv and its Go package is released with the new
					// semantic convention for build_id, replace these hard coded
					// strings.
					attrMgr.AppendOptionalString(mapping.AttributeIndices(),
						semconv.ProcessExecutableBuildIDGnuKey,
						ei.GnuBuildID)
					attrMgr.AppendOptionalString(mapping.AttributeIndices(),
						semconv.ProcessExecutableBuildIDHtlhashKey,
						traceInfo.Files[i].StringNoQuotes())
				}
				loc.SetMappingIndex(locationMappingIndex)
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originated from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as a Line message:
				line := loc.Line().AppendEmpty()

				fileIDInfoLock, exists := p.Frames.GetAndRefresh(traceInfo.Files[i],
					FramesCacheLifetime)
				if !exists {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					line.SetFunctionIndex(createFunctionEntry(funcMap,
						"UNREPORTED", frameKind.String()))
				} else {
					fileIDInfo := fileIDInfoLock.RLock()
					if si, exists := (*fileIDInfo)[traceInfo.Linenos[i]]; exists {
						line.SetLine(int64(si.LineNumber))

						line.SetFunctionIndex(createFunctionEntry(funcMap,
							si.FunctionName, si.FilePath))
					} else {
						// At this point, we do not have enough information for the frame.
						// Therefore, we report a dummy entry and use the interpreter as filename.
						// To differentiate this case from the case where no information about
						// the file ID is available at all, we use a different name for reported
						// function.
						line.SetFunctionIndex(createFunctionEntry(funcMap,
							"UNRESOLVED", frameKind.String()))
					}
					fileIDInfoLock.RUnlock(&fileIDInfo)
				}

				// To be compliant with the protocol, generate a dummy mapping entry.
				loc.SetMappingIndex(getDummyMappingIndex(fileIDtoMapping, stringMap,
					attrMgr, profile, traceInfo.Files[i]))
			}
		}

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

		for key, value := range traceInfo.EnvVars {
			attrMgr.AppendOptionalString(
				sample.AttributeIndices(),
				attribute.Key("env."+key),
				value)
		}

		if p.ExtraSampleAttrProd != nil {
			extra := p.ExtraSampleAttrProd.ExtraSampleAttrs(attrMgr, traceKey.ExtraMeta)
			sample.AttributeIndices().Append(extra...)
		}

		sample.SetLocationsLength(int32(len(traceInfo.FrameTypes)))
		locationIndex += sample.LocationsLength()
	}
	log.Debugf("Reporting OTLP profile with %d samples", profile.Sample().Len())

	// Populate the deduplicated functions into profile.
	funcTable := profile.FunctionTable()
	funcTable.EnsureCapacity(len(funcMap))
	for range funcMap {
		funcTable.AppendEmpty()
	}
	for v, idx := range funcMap {
		f := funcTable.At(int(idx))
		f.SetNameStrindex(getStringMapIndex(stringMap, v.Name))
		f.SetFilenameStrindex(getStringMapIndex(stringMap, v.FileName))
	}

	// When ranging over stringMap, the order will be according to the
	// hash value of the key. To get the correct order for profile.StringTable,
	// put the values in stringMap, in the correct array order.
	stringTable := make([]string, len(stringMap))
	for v, idx := range stringMap {
		stringTable[idx] = v
	}

	for _, v := range stringTable {
		profile.StringTable().Append(v)
	}

	// profile.LocationIndices is not optional, and we only write elements into
	// profile.Location that at least one sample references.
	for i := int32(0); i < int32(profile.LocationTable().Len()); i++ {
		profile.LocationIndices().Append(i)
	}

	profile.SetDuration(endTS - startTS)
	profile.SetStartTime(startTS)
}

// getStringMapIndex inserts or looks up the index for value in stringMap.
func getStringMapIndex(stringMap map[string]int32, value string) int32 {
	if idx, exists := stringMap[value]; exists {
		return idx
	}

	idx := int32(len(stringMap))
	stringMap[value] = idx

	return idx
}

// createFunctionEntry adds a new function and returns its reference index.
func createFunctionEntry(funcMap map[samples.FuncInfo]int32,
	name string, fileName string) int32 {
	key := samples.FuncInfo{
		Name:     name,
		FileName: fileName,
	}
	if idx, exists := funcMap[key]; exists {
		return idx
	}

	idx := int32(len(funcMap))
	funcMap[key] = idx

	return idx
}

// getDummyMappingIndex inserts or looks up an entry for interpreted FileIDs.
func getDummyMappingIndex(fileIDtoMapping map[libpf.FileID]int32,
	stringMap map[string]int32, attrMgr *samples.AttrTableManager, profile pprofile.Profile,
	fileID libpf.FileID) int32 {
	if mappingIndex, exists := fileIDtoMapping[fileID]; exists {
		return mappingIndex
	}

	locationMappingIndex := int32(len(fileIDtoMapping))
	fileIDtoMapping[fileID] = locationMappingIndex

	mapping := profile.MappingTable().AppendEmpty()
	mapping.SetFilenameStrindex(getStringMapIndex(stringMap, ""))
	attrMgr.AppendOptionalString(mapping.AttributeIndices(),
		semconv.ProcessExecutableBuildIDHtlhashKey,
		fileID.StringNoQuotes())
	return locationMappingIndex
}
