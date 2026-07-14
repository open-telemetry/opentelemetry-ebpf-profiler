package pdata // import "go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"

import (
	"hash/fnv"

	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/orderedset"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// locationInfo is a helper used to deduplicate Locations.
type locationInfo struct {
	address       uint64
	mappingIndex  int32
	frameType     libpf.FrameType
	hasLine       bool
	lineNumber    int64
	columnNumber  int64
	functionIndex int32
}

// funcInfo is a helper used to deduplicate Functions.
type funcInfo struct {
	nameIdx     int32
	fileNameIdx int32
}

// stackInfo is a helper used to deduplicate Stacks.
type stackInfo struct {
	locationIndicesHash uint64
}

// hashLocationIndices computes a hash for a slice of location indices.
func hashLocationIndices(locationIndices []int32) uint64 {
	h := fnv.New64a()
	h.Write(pfunsafe.FromSlice(locationIndices))
	return h.Sum64()
}

// appendFramesAsStack walks the frames of a single trace, adding any not-yet-seen
// mappings, locations and functions to the shared dictionary tables (with their
// build-ID and frame-type attributes), then deduplicates the resulting stack.
// It returns the index of the stack in the dictionary's StackTable.
//
// This is the single source of truth for turning a libpf.Frames into a stack
// index. Both the main profile path (setProfile) and the inuse/live-heap path
// (appendInuseProfiles) call it so their mapping/location/stack encoding, and
// crucially the attributes attached to them, cannot drift apart.
func appendFramesAsStack(
	frames libpf.Frames,
	dic pprofile.ProfilesDictionary,
	attrMgr *samples.AttrTableManager,
	stringSet orderedset.OrderedSet[string],
	funcSet orderedset.OrderedSet[funcInfo],
	mappingSet orderedset.OrderedSet[libpf.FrameMapping],
	locationSet orderedset.OrderedSet[locationInfo],
	stackSet orderedset.OrderedSet[stackInfo],
) int32 {
	locationIndices := make([]int32, 0, len(frames))
	// Walk every frame of the trace.
	for _, uniqueFrame := range frames {
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
	return stackIdx
}

// linkInfo is a helper used to deduplicate Links.
type linkInfo struct {
	spanID  libpf.APMSpanID
	traceID libpf.APMTraceID
}
