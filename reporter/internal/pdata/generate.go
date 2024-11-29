// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"crypto/rand"
	"slices"
	"strconv"

	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
)

// Generate generates a pdata request out of internal profiles data, to be
// exported.
func (p Pdata) Generate(events map[samples.TraceAndMetaKey]*samples.TraceEvents) pprofile.Profiles {
	profiles := pprofile.NewProfiles()
	rp := profiles.ResourceProfiles().AppendEmpty()

	sp := rp.ScopeProfiles().AppendEmpty()

	prof := sp.Profiles().AppendEmpty()
	prof.SetProfileID(pprofile.ProfileID(mkProfileID()))
	p.setProfile(events, prof)

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

	// attributeMap is a temporary helper that maps attribute values to
	// their respective indices.
	// This is to ensure that AttributeTable does not contain duplicates.
	attributeMap := make(map[string]int32)

	st := profile.SampleType().AppendEmpty()
	st.SetTypeStrindex(getStringMapIndex(stringMap, "samples"))
	st.SetUnitStrindex(getStringMapIndex(stringMap, "count"))

	pt := profile.PeriodType()
	pt.SetTypeStrindex(getStringMapIndex(stringMap, "cpu"))
	pt.SetUnitStrindex(getStringMapIndex(stringMap, "nanoseconds"))
	profile.SetPeriod(1e9 / int64(p.samplesPerSecond))

	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]int32)

	var locationIndex int32
	var startTS, endTS pcommon.Timestamp
	for traceKey, traceInfo := range events {
		sample := profile.Sample().AppendEmpty()
		sample.SetLocationsStartIndex(locationIndex)

		slices.Sort(traceInfo.Timestamps)
		startTS = pcommon.Timestamp(traceInfo.Timestamps[0])
		endTS = pcommon.Timestamp(traceInfo.Timestamps[len(traceInfo.Timestamps)-1])

		sample.TimestampsUnixNano().FromRaw(traceInfo.Timestamps)
		sample.Value().Append(1)

		// Walk every frame of the trace.
		for i := range traceInfo.FrameTypes {
			frameAttributes := addProfileAttributes(profile, []samples.AttrKeyValue[string]{
				{Key: "profile.frame.type", Value: traceInfo.FrameTypes[i].String()},
			}, attributeMap)

			loc := profile.LocationTable().AppendEmpty()
			loc.SetAddress(uint64(traceInfo.Linenos[i]))
			loc.AttributeIndices().FromRaw(frameAttributes)

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

					ei, exists := p.Executables.GetAndRefresh(traceInfo.Files[i], ...)

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = "UNKNOWN"
					if exists {
						fileName = ei.FileName
					}

					mappingAttributes := addProfileAttributes(
						profile,
						[]samples.AttrKeyValue[string]{
							// Once SemConv and its Go package is released with the new
							// semantic convention for build_id, replace these hard coded
							// strings.
							{Key: "process.executable.build_id.gnu", Value: ei.GnuBuildID},
							{Key: "process.executable.build_id.htlhash",
								Value: traceInfo.Files[i].StringNoQuotes()},
						},
						attributeMap,
					)

					mapping := profile.MappingTable().AppendEmpty()
					mapping.SetMemoryStart(uint64(traceInfo.MappingStarts[i]))
					mapping.SetMemoryLimit(uint64(traceInfo.MappingEnds[i]))
					mapping.SetFileOffset(traceInfo.MappingFileOffsets[i])
					mapping.SetFilenameStrindex(getStringMapIndex(stringMap, fileName))
					mapping.AttributeIndices().FromRaw(mappingAttributes)
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

				fileIDInfoLock, exists := p.Frames.Get(traceInfo.Files[i])
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
					profile, traceInfo.Files[i]))
			}
		}

		sampleAttrs := append(addProfileAttributes(profile, []samples.AttrKeyValue[string]{
			{Key: string(semconv.ContainerIDKey), Value: traceKey.ContainerID},
			{Key: string(semconv.ThreadNameKey), Value: traceKey.Comm},
			{Key: string(semconv.ServiceNameKey), Value: traceKey.ApmServiceName},
		}, attributeMap), addProfileAttributes(profile, []samples.AttrKeyValue[int64]{
			{Key: string(semconv.ProcessPIDKey), Value: traceKey.Pid},
		}, attributeMap)...)

		sample.AttributeIndices().FromRaw(sampleAttrs)

		sample.SetLocationsLength(int32(len(traceInfo.FrameTypes)))
		locationIndex += sample.LocationsLength()
	}
	log.Debugf("Reporting OTLP profile with %d samples", profile.Sample().Len())

	// Populate the deduplicated functions into profile.
	for v := range funcMap {
		f := profile.FunctionTable().AppendEmpty()
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

// addProfileAttributes adds attributes to Profile.attribute_table and returns
// the indices to these attributes.
func addProfileAttributes[T string | int64](profile pprofile.Profile,
	attributes []samples.AttrKeyValue[T], attributeMap map[string]int32) []int32 {
	indices := make([]int32, 0, len(attributes))

	addAttr := func(attr samples.AttrKeyValue[T]) {
		var attributeCompositeKey string
		var attributeValue any

		switch val := any(attr.Value).(type) {
		case string:
			if !attr.Required && val == "" {
				return
			}
			attributeCompositeKey = attr.Key + "_" + val
			attributeValue = val
		case int64:
			attributeCompositeKey = attr.Key + "_" + strconv.Itoa(int(val))
			attributeValue = val
		default:
			log.Error("Unsupported attribute value type. Only string and int64 are supported.")
			return
		}

		if attributeIndex, exists := attributeMap[attributeCompositeKey]; exists {
			indices = append(indices, attributeIndex)
			return
		}
		newIndex := int32(profile.AttributeTable().Len())
		indices = append(indices, newIndex)

		newAttr := profile.AttributeTable().AppendEmpty()
		newAttr.SetKey(attr.Key)
		switch v := attributeValue.(type) {
		case int64:
			newAttr.Value().SetInt(v)
		case string:
			newAttr.Value().SetStr(v)
		}

		attributeMap[attributeCompositeKey] = newIndex
	}

	for i := range attributes {
		addAttr(attributes[i])
	}

	return indices
}

// getDummyMappingIndex inserts or looks up an entry for interpreted FileIDs.
func getDummyMappingIndex(fileIDtoMapping map[libpf.FileID]int32,
	stringMap map[string]int32, profile pprofile.Profile,
	fileID libpf.FileID) int32 {
	if mappingIndex, exists := fileIDtoMapping[fileID]; exists {
		return mappingIndex
	}

	locationMappingIndex := int32(len(fileIDtoMapping))
	fileIDtoMapping[fileID] = locationMappingIndex

	mapping := profile.MappingTable().AppendEmpty()
	mapping.SetFilenameStrindex(getStringMapIndex(stringMap, ""))
	return locationMappingIndex
}
