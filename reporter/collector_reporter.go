// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"bufio"
	"context"
	"fmt"
	"maps"
	"os"
	"slices"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*CollectorReporter)(nil)

// OTLPReporter receives and transforms information to be Collector Collector compliant.
type CollectorReporter struct {
	cfg          *Config
	nextConsumer consumerprofiles.Profiles

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan struct{}

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, execInfo]

	// cgroupv2ID caches PID to container ID information for cgroupv2 containers.
	cgroupv2ID *lru.SyncedLRU[libpf.PID, string]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[traceAndMetaKey]*traceEvents]

	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int
}

// NewCollector builds a new CollectorReporter
func NewCollector(cfg *Config, nextConsumer consumerprofiles.Profiles) (*CollectorReporter, error) {
	executables, err := lru.NewSynced[libpf.FileID, execInfo](cfg.CacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](cfg.CacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	cgroupv2ID, err := lru.NewSynced[libpf.PID, string](cfg.CGroupCacheElements,
		func(pid libpf.PID) uint32 { return uint32(pid) })
	if err != nil {
		return nil, err
	}
	// Set a lifetime to reduce risk of invalid data in case of PID reuse.
	cgroupv2ID.SetLifetime(90 * time.Second)

	// Next step: Dynamically configure the size of this LRU.
	// Currently, we use the length of the JSON array in
	// hostmetadata/hostmetadata.json.
	hostmetadata, err := lru.NewSynced[string, string](115, hashString)
	if err != nil {
		return nil, err
	}

	return &CollectorReporter{
		cfg:          cfg,
		nextConsumer: nextConsumer,

		executables:  executables,
		frames:       frames,
		hostmetadata: hostmetadata,
		traceEvents:  xsync.NewRWMutex(map[traceAndMetaKey]*traceEvents{}),
		cgroupv2ID:   cgroupv2ID,

		samplesPerSecond: cfg.SamplesPerSecond,
	}, nil
}

func (r *CollectorReporter) Start(context.Context) error {
	go func() {
		tick := time.NewTicker(r.cfg.ReportInterval)
		defer tick.Stop()
		purgeTick := time.NewTicker(5 * time.Minute)
		defer purgeTick.Stop()

		for {
			select {
			case <-r.stopSignal:
				return
			case <-tick.C:
				if err := r.reportProfile(context.Background()); err != nil {
					log.Errorf("Request failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(r.cfg.ReportInterval, 0.2))
			case <-purgeTick.C:
				// Allow the GC to purge expired entries to avoid memory leaks.
				r.executables.PurgeExpired()
				r.frames.PurgeExpired()
			}
		}
	}()

	return nil
}

// ExecutableKnown returns true if the metadata of the Executable specified by fileID is
// cached in the reporter.
func (r *CollectorReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := r.executables.Get(fileID)
	return known
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *CollectorReporter) ExecutableMetadata(args *ExecutableMetadataArgs) {
	r.executables.Add(args.FileID, execInfo{
		fileName:   args.FileName,
		gnuBuildID: args.GnuBuildID,
	})
}

// FrameKnown return true if the metadata of the Frame specified by frameID is
// cached in the reporter.
func (r *CollectorReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := r.frames.Get(frameID.FileID()); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		_, known = (*frameMap)[frameID.AddressOrLine()]
	}
	return known
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *CollectorReporter) FrameMetadata(args *FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()

	if frameMapLock, exists := r.frames.Get(fileID); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		sourceFile := args.SourceFile
		if sourceFile == "" {
			// The new SourceFile may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				sourceFile = s.filePath
			}
		}

		(*frameMap)[addressOrLine] = sourceInfo{
			lineNumber:     args.SourceLine,
			filePath:       sourceFile,
			functionOffset: args.FunctionOffset,
			functionName:   args.FunctionName,
		}
		return
	}

	v := make(map[libpf.AddressOrLineno]sourceInfo)
	v[addressOrLine] = sourceInfo{
		lineNumber:     args.SourceLine,
		filePath:       args.SourceFile,
		functionOffset: args.FunctionOffset,
		functionName:   args.FunctionName,
	}
	mu := xsync.NewRWMutex(v)
	r.frames.Add(fileID, &mu)
}

// GetMetrics returns internal metrics of CollectorReporter.
func (r *CollectorReporter) GetMetrics() Metrics {
	return Metrics{}
}

// ReportFramesForTrace is a NOP for CollectorReporter.
func (r *CollectorReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for CollectorReporter.
func (r *CollectorReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *TraceEventMeta) {
}

// ReportMetrics is a NOP for CollectorReporter.
func (r *CollectorReporter) ReportMetrics(_ uint32, _ []uint32, _ []int64) {}

func (r *CollectorReporter) Stop() {
	close(r.stopSignal)
}

// ReportHostMetadata enqueues host metadata.
func (r *CollectorReporter) ReportHostMetadata(metadataMap map[string]string) {
	for k, v := range metadataMap {
		r.hostmetadata.Add(k, v)
	}
}

func (r *CollectorReporter) SupportsReportTraceEvent() bool { return true }

// ReportHostMetadataBlocking enqueues host metadata.
func (r *CollectorReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	r.ReportHostMetadata(metadataMap)
	return nil
}

// ReportTraceEvent enqueues reported trace events for the Collector reporter.
func (r *CollectorReporter) ReportTraceEvent(trace *libpf.Trace, meta *TraceEventMeta) {
	if r.nextConsumer == nil {
		return
	}

	traceEventsMap := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEventsMap)

	containerID, err := r.lookupCgroupv2(meta.PID)
	if err != nil {
		log.Debugf("Failed to get a cgroupv2 ID as container ID for PID %d: %v",
			meta.PID, err)
	}

	key := traceAndMetaKey{
		hash:           trace.Hash,
		comm:           meta.Comm,
		apmServiceName: meta.APMServiceName,
		containerID:    containerID,
	}

	if events, exists := (*traceEventsMap)[key]; exists {
		events.timestamps = append(events.timestamps, uint64(meta.Timestamp))
		(*traceEventsMap)[key] = events
		return
	}

	(*traceEventsMap)[key] = &traceEvents{
		files:              trace.Files,
		linenos:            trace.Linenos,
		frameTypes:         trace.FrameTypes,
		mappingStarts:      trace.MappingStart,
		mappingEnds:        trace.MappingEnd,
		mappingFileOffsets: trace.MappingFileOffsets,
		timestamps:         []uint64{uint64(meta.Timestamp)},
	}
}

// getProfile sets the data an OTLP profile with all collected samples up to
// this moment.
func (r *CollectorReporter) setProfile(profile pprofile.Profile) (startTS,
	endTS pcommon.Timestamp) {
	traceEvents := r.traceEvents.WLock()
	samples := maps.Clone(*traceEvents)
	clear(*traceEvents)
	r.traceEvents.WUnlock(&traceEvents)

	// stringMap is a temporary helper that will build the StringTable.
	// By specification, the first element should be empty.
	stringMap := make(map[string]uint32)
	stringMap[""] = 0

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]uint64)
	funcMap[funcInfo{name: "", fileName: ""}] = 0

	// attributeMap is a temporary helper that maps attribute values to
	// their respective indices.
	// This is to ensure that AttributeTable does not contain duplicates.
	attributeMap := make(map[string]uint64)

	st := profile.SampleType().AppendEmpty()
	st.SetType(int64(getStringMapIndex(stringMap, "samples")))
	st.SetUnit(int64(getStringMapIndex(stringMap, "count")))

	pt := profile.PeriodType()
	pt.SetType(int64(getStringMapIndex(stringMap, "cpu")))
	pt.SetUnit(int64(getStringMapIndex(stringMap, "nanoseconds")))
	profile.SetPeriod(1e9 / int64(r.samplesPerSecond))

	locationIndex := uint64(0)

	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]uint64)

	for traceKey, traceInfo := range samples {
		sample := profile.Sample().AppendEmpty()
		sample.SetLocationsStartIndex(locationIndex)

		sample.SetStacktraceIdIndex(getStringMapIndex(stringMap,
			traceKey.hash.Base64()))

		slices.Sort(traceInfo.timestamps)
		startTS = pcommon.Timestamp(traceInfo.timestamps[0])
		endTS = pcommon.Timestamp(traceInfo.timestamps[len(traceInfo.timestamps)-1])

		sample.TimestampsUnixNano().FromRaw(traceInfo.timestamps)
		sample.Value().Append(1)

		// Walk every frame of the trace.
		for i := range traceInfo.frameTypes {
			frameAttributes := addPdataProfileAttributes(profile, []attrKeyValue{
				{key: "profile.frame.type", value: traceInfo.frameTypes[i].String()},
			}, attributeMap)

			loc := profile.Location().AppendEmpty()
			loc.SetAddress(uint64(traceInfo.linenos[i]))
			loc.Attributes().FromRaw(frameAttributes)

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

					ei, exists := r.executables.Get(traceInfo.files[i])

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = "UNKNOWN"
					if exists {
						fileName = ei.fileName
					}

					mappingAttributes := addPdataProfileAttributes(profile, []attrKeyValue{
						// Once SemConv and its Go package is released with the new
						// semantic convention for build_id, replace these hard coded
						// strings.
						{key: "process.executable.build_id.gnu", value: ei.gnuBuildID},
						{key: "process.executable.build_id.profiling",
							value: traceInfo.files[i].StringNoQuotes()},
					}, attributeMap)

					mapping := profile.Mapping().AppendEmpty()
					mapping.SetMemoryStart(uint64(traceInfo.mappingStarts[i]))
					mapping.SetMemoryLimit(uint64(traceInfo.mappingEnds[i]))
					mapping.SetFileOffset(traceInfo.mappingFileOffsets[i])
					mapping.SetFilename(int64(getStringMapIndex(stringMap, fileName)))
					mapping.Attributes().FromRaw(mappingAttributes)
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

				fileIDInfoLock, exists := r.frames.Get(traceInfo.files[i])
				if !exists {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					line.SetFunctionIndex(createFunctionEntry(funcMap,
						"UNREPORTED", frameKind.String()))
				} else {
					fileIDInfo := fileIDInfoLock.RLock()
					if si, exists := (*fileIDInfo)[traceInfo.linenos[i]]; exists {
						line.SetLine(int64(si.lineNumber))

						line.SetFunctionIndex(createFunctionEntry(funcMap,
							si.functionName, si.filePath))
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
				loc.SetMappingIndex(getDummyPdataMappingIndex(fileIDtoMapping, stringMap,
					profile, traceInfo.files[i]))
			}
		}

		sampleAttrs := addPdataProfileAttributes(profile, []attrKeyValue{
			{key: string(semconv.ContainerIDKey), value: traceKey.containerID},
			{key: string(semconv.ThreadNameKey), value: traceKey.comm},
			{key: string(semconv.ServiceNameKey), value: traceKey.apmServiceName},
		}, attributeMap)
		sample.Attributes().FromRaw(sampleAttrs)

		sample.SetLocationsLength(uint64(len(traceInfo.frameTypes)))
		locationIndex += sample.LocationsLength()
	}
	log.Debugf("Reporting OTLP profile with %d samples", profile.Sample().Len())

	// Populate the deduplicated functions into profile.
	for v := range funcMap {
		f := profile.Function().AppendEmpty()
		f.SetName(int64(getStringMapIndex(stringMap, v.name)))
		f.SetFilename(int64(getStringMapIndex(stringMap, v.fileName)))
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
	for i := int64(0); i < int64(profile.Location().Len()); i++ {
		profile.LocationIndices().Append(i)
	}

	profile.SetDuration(endTS - startTS)
	profile.SetStartTime(startTS)

	return startTS, endTS
}

// reportProfile sends a profile to the next consumer
func (r *CollectorReporter) reportProfile(ctx context.Context) error {
	profiles := pprofile.NewProfiles()
	rp := profiles.ResourceProfiles().AppendEmpty()

	sp := rp.ScopeProfiles().AppendEmpty()

	pc := sp.Profiles().AppendEmpty()
	pc.SetProfileID(pprofile.ProfileID(mkProfileID()))

	startTS, endTS := r.setProfile(pc.Profile())
	pc.SetStartTime(startTS)
	pc.SetEndTime(endTS)

	if pc.Profile().Sample().Len() == 0 {
		log.Debugf("Skip sending of profile to collector with no samples")
		return nil
	}

	return r.nextConsumer.ConsumeProfiles(ctx, profiles)
}

// lookupCgroupv2 returns the cgroupv2 ID for pid.
func (r *CollectorReporter) lookupCgroupv2(pid libpf.PID) (string, error) {
	id, ok := r.cgroupv2ID.Get(pid)
	if ok {
		return id, nil
	}

	// Slow path
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	var genericCgroupv2 string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)
	var pathParts []string
	for scanner.Scan() {
		line := scanner.Text()
		pathParts = cgroupv2PathPattern.FindStringSubmatch(line)
		if pathParts == nil {
			log.Debugf("Could not extract cgroupv2 path from line: %s", line)
			continue
		}
		genericCgroupv2 = pathParts[1]
		break
	}

	// Cache the cgroupv2 information.
	// To avoid busy lookups, also empty cgroupv2 information is cached.
	r.cgroupv2ID.Add(pid, genericCgroupv2)

	return genericCgroupv2, nil
}

// addPdataProfileAttributes adds attributes to Profile.attribute_table and returns
// the indices to these attributes.
func addPdataProfileAttributes(profile pprofile.Profile,
	attributes []attrKeyValue, attributeMap map[string]uint64) []uint64 {
	indices := make([]uint64, 0, len(attributes))

	addAttr := func(attr attrKeyValue) {
		if attr.value == "" {
			return
		}
		attributeCompositeKey := attr.key + "_" + attr.value
		if attributeIndex, exists := attributeMap[attributeCompositeKey]; exists {
			indices = append(indices, attributeIndex)
			return
		}
		newIndex := uint64(profile.AttributeTable().Len())
		indices = append(indices, newIndex)
		profile.AttributeTable().PutStr(attr.key, attr.value)
		attributeMap[attributeCompositeKey] = newIndex
	}

	for i := range attributes {
		addAttr(attributes[i])
	}

	return indices
}

// getDummyPdataMappingIndex inserts or looks up an entry for interpreted FileIDs.
func getDummyPdataMappingIndex(fileIDtoMapping map[libpf.FileID]uint64,
	stringMap map[string]uint32, profile pprofile.Profile,
	fileID libpf.FileID) uint64 {
	var locationMappingIndex uint64
	if tmpMappingIndex, exists := fileIDtoMapping[fileID]; exists {
		locationMappingIndex = tmpMappingIndex
	} else {
		idx := uint64(len(fileIDtoMapping))
		fileIDtoMapping[fileID] = idx
		locationMappingIndex = idx

		mapping := profile.Mapping().AppendEmpty()
		mapping.SetFilename(int64(getStringMapIndex(stringMap, "")))
	}
	return locationMappingIndex
}
