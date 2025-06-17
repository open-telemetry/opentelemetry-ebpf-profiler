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
	FrameMapLifetime        = 1 * time.Hour
)

// Generate generates a pdata request out of internal profiles data, to be
// exported.
func (p *Pdata) Generate(events map[libpf.Origin]samples.KeyToEventMapping) pprofile.Profiles {
	profiles := pprofile.NewProfiles()
	rp := profiles.ResourceProfiles().AppendEmpty()
	sp := rp.ScopeProfiles().AppendEmpty()
	for _, origin := range []libpf.Origin{
		support.TraceOriginSampling,
		support.TraceOriginOffCPU,
	} {
		if len(events[origin]) == 0 {
			// Do not append empty profiles, if there
			// is not profiling data for this origin.
			continue
		}
		prof := sp.Profiles().AppendEmpty()
		prof.SetProfileID(pprofile.ProfileID(mkProfileID()))
		p.setProfile(profiles.ProfilesDictionary(), origin, events[origin], prof)
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
	dic pprofile.ProfilesDictionary,
	origin libpf.Origin,
	events map[samples.TraceAndMetaKey]*samples.TraceEvents,
	profile pprofile.Profile,
) {
	// stringMap is a temporary helper that will build the StringTable.
	// By specification, the first element should be empty.
	strDicOffset := int32(dic.StringTable().Len())
	stringMap := make(map[string]int32)
	if strDicOffset == 0 {
		stringMap[""] = strDicOffset
	}

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcDicOffset := int32(dic.FunctionTable().Len())
	funcMap := make(map[samples.FuncInfo]int32)
	if funcDicOffset == 0 {
		funcMap[samples.FuncInfo{Name: "", FileName: ""}] = 0
	}

	st := profile.SampleType().AppendEmpty()
	switch origin {
	case support.TraceOriginSampling:
		st.SetTypeStrindex(getStringMapIndex(stringMap, strDicOffset, "samples"))
		st.SetUnitStrindex(getStringMapIndex(stringMap, strDicOffset, "count"))

		pt := profile.PeriodType()
		pt.SetTypeStrindex(getStringMapIndex(stringMap, strDicOffset, "cpu"))
		pt.SetUnitStrindex(getStringMapIndex(stringMap, strDicOffset, "nanoseconds"))

		profile.SetPeriod(1e9 / int64(p.samplesPerSecond))
	case support.TraceOriginOffCPU:
		st.SetTypeStrindex(getStringMapIndex(stringMap, strDicOffset, "events"))
		st.SetUnitStrindex(getStringMapIndex(stringMap, strDicOffset, "nanoseconds"))
	default:
		log.Errorf("Generating profile for unsupported origin %d", origin)
		return
	}

	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]int32)

	attrMgr := samples.NewAttrTableManager(dic.AttributeTable())
	locationIndex := int32(dic.LocationTable().Len())
	startLocationIndex := locationIndex
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
			loc := dic.LocationTable().AppendEmpty()
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
					fileName := "UNKNOWN"
					if exists {
						fileName = ei.FileName
					}

					mapping := dic.MappingTable().AppendEmpty()
					mapping.SetMemoryStart(uint64(traceInfo.MappingStarts[i]))
					mapping.SetMemoryLimit(uint64(traceInfo.MappingEnds[i]))
					mapping.SetFileOffset(traceInfo.MappingFileOffsets[i])
					mapping.SetFilenameStrindex(getStringMapIndex(stringMap, strDicOffset,
						fileName))

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

				if si, exists := p.Frames.GetAndRefresh(
					libpf.NewFrameID(traceInfo.Files[i], traceInfo.Linenos[i]),
					FramesCacheLifetime); exists {
					line.SetLine(int64(si.LineNumber))

					line.SetFunctionIndex(createFunctionEntry(funcMap, funcDicOffset,
						si.FunctionName, si.FilePath))
				} else {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					// To differentiate this case from the case where no information about
					// the file ID is available at all, we use a different name for reported
					// function.
					line.SetFunctionIndex(createFunctionEntry(funcMap, funcDicOffset,
						"UNRESOLVED", frameKind.String()))
				}

				// To be compliant with the protocol, generate a dummy mapping entry.
				loc.SetMappingIndex(getDummyMappingIndex(fileIDtoMapping, stringMap, strDicOffset,
					attrMgr, dic, traceInfo.Files[i]))
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
		attrMgr.AppendInt(sample.AttributeIndices(),
			semconv.ThreadIDKey, traceKey.Tid)

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
	funcTable := dic.FunctionTable()
	funcTable.EnsureCapacity(len(funcMap) + int(funcDicOffset))
	for range funcMap {
		funcTable.AppendEmpty()
	}
	for v, idx := range funcMap {
		f := funcTable.At(int(idx))
		f.SetNameStrindex(getStringMapIndex(stringMap, strDicOffset, v.Name))
		f.SetFilenameStrindex(getStringMapIndex(stringMap, strDicOffset, v.FileName))
	}

	// When ranging over stringMap, the order will be according to the
	// hash value of the key. To get the correct order for profile.StringTable,
	// put the values in stringMap, in the correct array order.
	tmpStringTable := make([]string, len(stringMap)+int(strDicOffset))
	for v, idx := range stringMap {
		tmpStringTable[idx] = v
	}

	strTable := dic.StringTable()
	strTable.EnsureCapacity(len(stringMap) + int(strDicOffset))
	for _, value := range tmpStringTable[strDicOffset:] {
		dic.StringTable().Append(value)
	}

	// profile.LocationIndices is not optional, and we only write elements into
	// profile.Location that at least one sample references.
	for i := startLocationIndex; i < locationIndex; i++ {
		profile.LocationIndices().Append(i)
	}

	profile.SetDuration(endTS - startTS)
	profile.SetStartTime(startTS)
}

// getStringMapIndex inserts or looks up the index for value in stringMap.
func getStringMapIndex(stringMap map[string]int32, offset int32, value string) int32 {
	if idx, exists := stringMap[value]; exists {
		return idx
	}

	idx := int32(len(stringMap)) + offset
	stringMap[value] = idx

	return idx
}

// createFunctionEntry adds a new function and returns its reference index.
func createFunctionEntry(funcMap map[samples.FuncInfo]int32, offset int32,
	name string, fileName string,
) int32 {
	key := samples.FuncInfo{
		Name:     name,
		FileName: fileName,
	}
	if idx, exists := funcMap[key]; exists {
		return idx
	}

	idx := int32(len(funcMap)) + offset
	funcMap[key] = idx

	return idx
}

// getDummyMappingIndex inserts or looks up an entry for interpreted FileIDs.
func getDummyMappingIndex(fileIDtoMapping map[libpf.FileID]int32,
	stringMap map[string]int32, strDicOffset int32, attrMgr *samples.AttrTableManager,
	dic pprofile.ProfilesDictionary,
	fileID libpf.FileID,
) int32 {
	if mappingIndex, exists := fileIDtoMapping[fileID]; exists {
		return mappingIndex
	}

	locationMappingIndex := int32(len(fileIDtoMapping))
	fileIDtoMapping[fileID] = locationMappingIndex

	mapping := dic.MappingTable().AppendEmpty()
	mapping.SetFilenameStrindex(getStringMapIndex(stringMap, strDicOffset, ""))
	attrMgr.AppendOptionalString(mapping.AttributeIndices(),
		semconv.ProcessExecutableBuildIDHtlhashKey,
		fileID.StringNoQuotes())
	return locationMappingIndex
}
