// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	lru "github.com/elastic/go-freelru"
	profiles "go.opentelemetry.io/proto/otlp/profiles/v1experimental"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
)

func walkFrames[P *profiles.Profile](
	profile P,
	traceInfo *traceEvents,
	executables *lru.SyncedLRU[libpf.FileID, execInfo],
	frames *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]],
	attributeMap map[string]uint64,
	fileIDtoMapping map[libpf.FileID]uint64,
	funcMap map[funcInfo]uint64,
	stringMap map[string]uint32,
) {
	// Walk every frame of the trace.
	for i := range traceInfo.frameTypes {
		frameAttributes := addProfileAttributes(profile, []attrKeyValue[string]{
			{key: "profile.frame.type", value: traceInfo.frameTypes[i].String()},
		}, attributeMap)
		loc := buildLoc(profile, uint64(traceInfo.linenos[i]), frameAttributes)

		switch frameKind := traceInfo.frameTypes[i]; frameKind {
		case libpf.NativeFrame:
			// As native frames are resolved in the backend, we use Mapping to
			// report these frames.

			var locationMappingIndex uint64
			if tmpMappingIndex, exists := fileIDtoMapping[traceInfo.files[i]]; exists {
				locationMappingIndex = tmpMappingIndex
			} else {
				idx := uint64(len(fileIDtoMapping))
				fileIDtoMapping[traceInfo.files[i]] = idx
				locationMappingIndex = idx

				appendProfileMapping(profile, i, traceInfo, executables, attributeMap, stringMap)
			}
			appendLocMappingIndex(loc, locationMappingIndex)
		case libpf.AbortFrame:
			// Next step: Figure out how the OTLP protocol
			// could handle artificial frames, like AbortFrame,
			// that are not originated from a native or interpreted
			// program.
		default:
			// Store interpreted frame information as a Line message:
			fileIDInfoLock, exists := frames.Get(traceInfo.files[i])

			var functionIndex uint64
			var lineNumber int64
			if !exists {
				// At this point, we do not have enough information for the frame.
				// Therefore, we report a dummy entry and use the interpreter as filename.
				functionIndex = createFunctionEntry(funcMap,
					"UNREPORTED", frameKind.String())
			} else {
				fileIDInfo := fileIDInfoLock.RLock()
				if si, exists := (*fileIDInfo)[traceInfo.linenos[i]]; exists {
					lineNumber = int64(si.lineNumber)

					functionIndex = createFunctionEntry(funcMap,
						si.functionName, si.filePath)
				} else {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					// To differentiate this case from the case where no information about
					// the file ID is available at all, we use a different name for reported
					// function.
					functionIndex = createFunctionEntry(funcMap,
						"UNRESOLVED", frameKind.String())
				}
				fileIDInfoLock.RUnlock(&fileIDInfo)
			}

			appendLocLine(loc, functionIndex, lineNumber)

			// To be compliant with the protocol, generate a dummy mapping entry.
			appendLocMappingIndex(loc, getDummyMappingIndex(fileIDtoMapping, stringMap,
				profile, traceInfo.files[i]))
		}
	}
}

func appendProfileMapping(
	profile any,
	i int,
	traceInfo *traceEvents,
	executables *lru.SyncedLRU[libpf.FileID, execInfo],
	attributeMap map[string]uint64,
	stringMap map[string]uint32,
) {
	execInfo, exists := executables.Get(traceInfo.files[i])

	// Next step: Select a proper default value,
	// if the name of the executable is not known yet.
	var fileName = "UNKNOWN"
	if exists {
		fileName = execInfo.fileName
	}

	switch prof := profile.(type) {
	case *profiles.Profile:
		mappingAttributes := addProfileAttributes(prof, []attrKeyValue[string]{
			// Once SemConv and its Go package is released with the new
			// semantic convention for build_id, replace these hard coded
			// strings.
			{key: "process.executable.build_id.gnu", value: execInfo.gnuBuildID},
			{key: "process.executable.build_id.profiling",
				value: traceInfo.files[i].StringNoQuotes()},
		}, attributeMap)

		prof.Mapping = append(prof.Mapping, &profiles.Mapping{
			// Id - Optional element we do not use.
			MemoryStart: uint64(traceInfo.mappingStarts[i]),
			MemoryLimit: uint64(traceInfo.mappingEnds[i]),
			FileOffset:  traceInfo.mappingFileOffsets[i],
			Filename:    int64(getStringMapIndex(stringMap, fileName)),
			Attributes:  mappingAttributes,
			// HasFunctions - Optional element we do not use.
			// HasFilenames - Optional element we do not use.
			// HasLineNumbers - Optional element we do not use.
			// HasInlinedFrames - Optional element we do not use.
		})
	default:
		// Nothing to do here
	}
}

func buildLoc(profile any, address uint64, attrs []uint64) any {
	switch profile.(type) {
	case *profiles.Profile:
		return &profiles.Location{
			// Id - Optional element we do not use.
			Address: address,
			// IsFolded - Optional element we do not use.
			Attributes: attrs,
		}
	default:
		return nil
	}
}

func appendLocMappingIndex(loc any, mappingIndex uint64) {
	switch l := loc.(type) {
	case *profiles.Location:
		l.MappingIndex = mappingIndex
	default:
		// Nothing to do here
	}
}

func appendLocLine(loc any, functionIndex uint64, lineNumber int64) {
	switch l := loc.(type) {
	case *profiles.Location:
		l.Line = append(l.Line, &profiles.Line{
			FunctionIndex: functionIndex,
			Line:          lineNumber,
		})
	default:
		// Nothing to do here
	}
}
