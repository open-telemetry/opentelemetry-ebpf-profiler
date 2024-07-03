/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"maps"
	"slices"
	"strconv"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/libpf/xsync"
	"github.com/elastic/otel-profiling-agent/util"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	otlpcollector "go.opentelemetry.io/proto/otlp/collector/profiles/v1experimental"
	common "go.opentelemetry.io/proto/otlp/common/v1"
	profiles "go.opentelemetry.io/proto/otlp/profiles/v1experimental"
	resource "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*OTLPReporter)(nil)

// execInfo enriches an executable with additional metadata.
type execInfo struct {
	fileName string
	buildID  string
}

// sourceInfo allows mapping a frame to its source origin.
type sourceInfo struct {
	lineNumber     util.SourceLineno
	functionOffset uint32
	functionName   string
	filePath       string
}

// funcInfo is a helper to construct profile.Function messages.
type funcInfo struct {
	name     string
	fileName string
}

// traceFramesCounts holds known information about a trace.
type traceFramesCounts struct {
	files              []libpf.FileID
	linenos            []libpf.AddressOrLineno
	frameTypes         []libpf.FrameType
	mappingStarts      []libpf.Address
	mappingEnds        []libpf.Address
	mappingFileOffsets []uint64
	comm               string
	podName            string
	containerName      string
	apmServiceName     string
	timestamps         []uint64 // in nanoseconds
}

// OTLPReporter receives and transforms information to be OTLP/profiles compliant.
type OTLPReporter struct {
	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// client for the connection to the receiver.
	client otlpcollector.ProfilesServiceClient

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// rpcStats stores gRPC related statistics.
	rpcStats *StatsHandlerImpl

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long-term storage information that might
	// be duplicated in other places but not accessible for OTLPReporter.

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// fallbackSymbols keeps track of FrameID to their symbol.
	fallbackSymbols *lru.SyncedLRU[libpf.FrameID, string]

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, execInfo]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[libpf.TraceHash]traceFramesCounts]

	// pkgGRPCOperationTimeout sets the time limit for GRPC requests.
	pkgGRPCOperationTimeout time.Duration
}

// hashString is a helper function for LRUs that use string as a key.
// Xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

func (r *OTLPReporter) SupportsReportTraceEvent() bool { return true }

// ReportTraceEvent enqueues reported trace events for the OTLP reporter.
func (r *OTLPReporter) ReportTraceEvent(trace *libpf.Trace,
	timestamp libpf.UnixTime64, comm, podName,
	containerName, apmServiceName string) {
	traceEvents := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEvents)

	if tr, exists := (*traceEvents)[trace.Hash]; exists {
		tr.timestamps = append(tr.timestamps, uint64(timestamp))
		(*traceEvents)[trace.Hash] = tr
		return
	}

	(*traceEvents)[trace.Hash] = traceFramesCounts{
		files:              trace.Files,
		linenos:            trace.Linenos,
		frameTypes:         trace.FrameTypes,
		mappingStarts:      trace.MappingStart,
		mappingEnds:        trace.MappingEnd,
		mappingFileOffsets: trace.MappingFileOffsets,
		comm:               comm,
		podName:            podName,
		containerName:      containerName,
		apmServiceName:     apmServiceName,
		timestamps:         []uint64{uint64(timestamp)},
	}
}

// ReportFramesForTrace is a NOP for OTLPReporter.
func (r *OTLPReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for OTLPReporter.
func (r *OTLPReporter) ReportCountForTrace(_ libpf.TraceHash, _ libpf.UnixTime64,
	_ uint16, _, _, _, _ string) {
}

// ReportFallbackSymbol enqueues a fallback symbol for reporting, for a given frame.
func (r *OTLPReporter) ReportFallbackSymbol(frameID libpf.FrameID, symbol string) {
	if _, exists := r.fallbackSymbols.Peek(frameID); exists {
		return
	}
	r.fallbackSymbols.Add(frameID, symbol)
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *OTLPReporter) ExecutableMetadata(_ context.Context,
	fileID libpf.FileID, fileName, buildID string) {
	r.executables.Add(fileID, execInfo{
		fileName: fileName,
		buildID:  buildID,
	})
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *OTLPReporter) FrameMetadata(fileID libpf.FileID, addressOrLine libpf.AddressOrLineno,
	lineNumber util.SourceLineno, functionOffset uint32, functionName, filePath string) {
	if frameMapLock, exists := r.frames.Get(fileID); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		if filePath == "" {
			// The new filePath may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				filePath = s.filePath
			}
		}

		(*frameMap)[addressOrLine] = sourceInfo{
			lineNumber:     lineNumber,
			functionOffset: functionOffset,
			functionName:   functionName,
			filePath:       filePath,
		}

		return
	}

	v := make(map[libpf.AddressOrLineno]sourceInfo)
	v[addressOrLine] = sourceInfo{
		lineNumber:     lineNumber,
		functionOffset: functionOffset,
		functionName:   functionName,
		filePath:       filePath,
	}
	r.frames.Add(fileID, xsync.NewRWMutex(v))
}

// ReportHostMetadata enqueues host metadata.
func (r *OTLPReporter) ReportHostMetadata(metadataMap map[string]string) {
	r.addHostmetadata(metadataMap)
}

// ReportHostMetadataBlocking enqueues host metadata.
func (r *OTLPReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	r.addHostmetadata(metadataMap)
	return nil
}

// addHostmetadata adds to and overwrites host metadata.
func (r *OTLPReporter) addHostmetadata(metadataMap map[string]string) {
	for k, v := range metadataMap {
		r.hostmetadata.Add(k, v)
	}
}

// ReportMetrics is a NOP for OTLPReporter.
func (r *OTLPReporter) ReportMetrics(_ uint32, _ []uint32, _ []int64) {}

// Stop triggers a graceful shutdown of OTLPReporter.
func (r *OTLPReporter) Stop() {
	close(r.stopSignal)
}

// GetMetrics returns internal metrics of OTLPReporter.
func (r *OTLPReporter) GetMetrics() Metrics {
	return Metrics{
		RPCBytesOutCount:  r.rpcStats.GetRPCBytesOut(),
		RPCBytesInCount:   r.rpcStats.GetRPCBytesIn(),
		WireBytesOutCount: r.rpcStats.GetWireBytesOut(),
		WireBytesInCount:  r.rpcStats.GetWireBytesIn(),
	}
}

// Start sets up and manages the reporting connection to a OTLP backend.
func Start(mainCtx context.Context, cfg *Config) (Reporter, error) {
	cacheSize := config.TraceCacheEntries()
	fallbackSymbols, err := lru.NewSynced[libpf.FrameID, string](cacheSize, libpf.FrameID.Hash32)
	if err != nil {
		return nil, err
	}

	executables, err := lru.NewSynced[libpf.FileID, execInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	// Next step: Dynamically configure the size of this LRU.
	// Currently, we use the length of the JSON array in
	// hostmetadata/hostmetadata.json.
	hostmetadata, err := lru.NewSynced[string, string](115, hashString)
	if err != nil {
		return nil, err
	}

	r := &OTLPReporter{
		name:                    cfg.Name,
		version:                 cfg.Version,
		stopSignal:              make(chan libpf.Void),
		pkgGRPCOperationTimeout: cfg.Times.GRPCOperationTimeout(),
		client:                  nil,
		rpcStats:                NewStatsHandler(),
		fallbackSymbols:         fallbackSymbols,
		executables:             executables,
		frames:                  frames,
		hostmetadata:            hostmetadata,
		traceEvents:             xsync.NewRWMutex(map[libpf.TraceHash]traceFramesCounts{}),
	}

	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	// Establish the gRPC connection before going on, waiting for a response
	// from the collectionAgent endpoint.
	// Use grpc.WithBlock() in setupGrpcConnection() for this to work.
	otlpGrpcConn, err := waitGrpcEndpoint(ctx, cfg, r.rpcStats)
	if err != nil {
		cancelReporting()
		close(r.stopSignal)
		return nil, err
	}
	r.client = otlpcollector.NewProfilesServiceClient(otlpGrpcConn)

	go func() {
		tick := time.NewTicker(cfg.Times.ReportInterval())
		defer tick.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-r.stopSignal:
				return
			case <-tick.C:
				if err := r.reportOTLPProfile(ctx); err != nil {
					log.Errorf("Request failed: %v", err)
				}
				tick.Reset(libpf.AddJitter(cfg.Times.ReportInterval(), 0.2))
			}
		}
	}()

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	// - close the gRPC connection with collection-agent
	go func() {
		<-r.stopSignal
		cancelReporting()
		if err := otlpGrpcConn.Close(); err != nil {
			log.Fatalf("Stopping connection of OTLP client client failed: %v", err)
		}
	}()

	return r, nil
}

// reportOTLPProfile creates and sends out an OTLP profile.
func (r *OTLPReporter) reportOTLPProfile(ctx context.Context) error {
	profile, startTS, endTS := r.getProfile()

	if len(profile.Sample) == 0 {
		log.Debugf("Skip sending of OTLP profile with no samples")
		return nil
	}

	pc := []*profiles.ProfileContainer{{
		ProfileId:         mkProfileID(),
		StartTimeUnixNano: startTS,
		EndTimeUnixNano:   endTS,
		// Attributes - Optional element we do not use.
		// DroppedAttributesCount - Optional element we do not use.
		// OriginalPayloadFormat - Optional element we do not use.
		// OriginalPayload - Optional element we do not use.
		Profile: profile,
	}}

	scopeProfiles := []*profiles.ScopeProfiles{{
		Profiles: pc,
		Scope: &common.InstrumentationScope{
			Name:    r.name,
			Version: r.version,
		},
		// SchemaUrl - This element is not well-defined yet. Therefore, we skip it.
	}}

	resourceProfiles := []*profiles.ResourceProfiles{{
		Resource:      r.getResource(),
		ScopeProfiles: scopeProfiles,
		// SchemaUrl - This element is not well-defined yet. Therefore, we skip it.
	}}

	req := otlpcollector.ExportProfilesServiceRequest{
		ResourceProfiles: resourceProfiles,
	}

	reqCtx, ctxCancel := context.WithTimeout(ctx, r.pkgGRPCOperationTimeout)
	defer ctxCancel()
	_, err := r.client.Export(reqCtx, &req)
	return err
}

// mkProfileID creates a random profile ID.
func mkProfileID() []byte {
	profileID := make([]byte, 16)
	_, err := rand.Read(profileID)
	if err != nil {
		return []byte("otel-profiling-agent")
	}
	return profileID
}

// getResource returns the OTLP resource information of the origin of the profiles.
// Next step: maybe extend this information with go.opentelemetry.io/otel/sdk/resource.
func (r *OTLPReporter) getResource() *resource.Resource {
	keys := r.hostmetadata.Keys()

	attributes := make([]*common.KeyValue, 0, len(keys)+6)

	addAttr := func(k attribute.Key, v string) {
		attributes = append(attributes, &common.KeyValue{
			Key:   string(k),
			Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: v}},
		})
	}

	// Add hostmedata to the attributes.
	for _, k := range keys {
		if v, ok := r.hostmetadata.Get(k); ok {
			addAttr(attribute.Key(k), v)
		}
	}

	// Add event specific attributes.
	// These attributes are also included in the host metadata, but with different names/keys.
	// That makes our hostmetadata attributes incompatible with OTEL collectors.
	// TODO: Make a final decision about project id.
	addAttr("profiling.project.id", strconv.FormatUint(uint64(config.ProjectID()), 10))
	addAttr(semconv.HostIDKey, strconv.FormatUint(config.HostID(), 10))
	addAttr(semconv.HostIPKey, config.IPAddress())
	addAttr(semconv.HostNameKey, config.Hostname())
	addAttr(semconv.ServiceVersionKey, r.version)
	addAttr("os.kernel", config.KernelVersion())

	return &resource.Resource{
		Attributes: attributes,
	}
}

// getProfile returns an OTLP profile containing all collected samples up to this moment.
func (r *OTLPReporter) getProfile() (profile *profiles.Profile, startTS uint64, endTS uint64) {
	traceEvents := r.traceEvents.WLock()
	samples := maps.Clone(*traceEvents)
	for key := range *traceEvents {
		delete(*traceEvents, key)
	}
	r.traceEvents.WUnlock(&traceEvents)

	// stringMap is a temporary helper that will build the StringTable.
	// By specification, the first element should be empty.
	stringMap := make(map[string]uint32)
	stringMap[""] = 0

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]uint64)
	funcMap[funcInfo{name: "", fileName: ""}] = 0

	numSamples := len(samples)
	profile = &profiles.Profile{
		// SampleType - Next step: Figure out the correct SampleType.
		Sample: make([]*profiles.Sample, 0, numSamples),
		SampleType: []*profiles.ValueType{{
			Type: int64(getStringMapIndex(stringMap, "samples")),
			Unit: int64(getStringMapIndex(stringMap, "count")),
		}},
		PeriodType: &profiles.ValueType{
			Type: int64(getStringMapIndex(stringMap, "cpu")),
			Unit: int64(getStringMapIndex(stringMap, "nanoseconds")),
		},
		Period: 1e9 / int64(config.SamplesPerSecond()),
		// LocationIndices - Optional element we do not use.
		// AttributeTable - Optional element we do not use.
		// AttributeUnits - Optional element we do not use.
		// LinkTable - Optional element we do not use.
		// DropFrames - Optional element we do not use.
		// KeepFrames - Optional element we do not use.
		// TimeNanos - Optional element we do not use.
		// DurationNanos - Optional element we do not use.
		// PeriodType - Optional element we do not use.
		// Period - Optional element we do not use.
		// Comment - Optional element we do not use.
		// DefaultSampleType - Optional element we do not use.
	}

	locationIndex := uint64(0)

	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]uint64)
	frameIDtoFunction := make(map[libpf.FrameID]uint64)

	for traceHash, traceInfo := range samples {
		sample := &profiles.Sample{}
		sample.LocationsStartIndex = locationIndex

		sample.StacktraceIdIndex = getStringMapIndex(stringMap,
			traceHash.Base64())

		timestamps, values := dedupSlice(traceInfo.timestamps)
		// dedupTimestamps returns a sorted list of timestamps, so
		// startTs and endTs can be used directly.
		startTS = timestamps[0]
		endTS = timestamps[len(timestamps)-1]

		sample.TimestampsUnixNano = timestamps
		sample.Value = values

		// Walk every frame of the trace.
		for i := range traceInfo.frameTypes {
			loc := &profiles.Location{
				// Id - Optional element we do not use.
				TypeIndex: getStringMapIndex(stringMap,
					traceInfo.frameTypes[i].String()),
				Address: uint64(traceInfo.linenos[i]),
				// IsFolded - Optional element we do not use.
				// Attributes - Optional element we do not use.
			}

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

					execInfo, exists := r.executables.Get(traceInfo.files[i])

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = "UNKNOWN"
					if exists {
						fileName = execInfo.fileName
					}

					profile.Mapping = append(profile.Mapping, &profiles.Mapping{
						// Id - Optional element we do not use.
						MemoryStart: uint64(traceInfo.mappingStarts[i]),
						MemoryLimit: uint64(traceInfo.mappingEnds[i]),
						FileOffset:  traceInfo.mappingFileOffsets[i],
						Filename:    int64(getStringMapIndex(stringMap, fileName)),
						BuildId: int64(getStringMapIndex(stringMap,
							traceInfo.files[i].StringNoQuotes())),
						BuildIdKind: *profiles.BuildIdKind_BUILD_ID_BINARY_HASH.Enum(),
						// Attributes - Optional element we do not use.
						// HasFunctions - Optional element we do not use.
						// HasFilenames - Optional element we do not use.
						// HasLineNumbers - Optional element we do not use.
						// HasInlinedFrames - Optional element we do not use.
					})
				}
				loc.MappingIndex = locationMappingIndex
			case libpf.KernelFrame:
				// Reconstruct frameID
				frameID := libpf.NewFrameID(traceInfo.files[i], traceInfo.linenos[i])
				// Store Kernel frame information as a Line message:
				line := &profiles.Line{}

				if tmpFunctionIndex, exists := frameIDtoFunction[frameID]; exists {
					line.FunctionIndex = tmpFunctionIndex
				} else {
					symbol, exists := r.fallbackSymbols.Get(frameID)
					if !exists {
						// TODO: choose a proper default value if the kernel symbol was not
						// reported yet.
						symbol = "UNKNOWN"
					}

					// Indicates "no source filename" for kernel frames.
					line.FunctionIndex = createFunctionEntry(funcMap,
						symbol, "")
				}
				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol, generate a placeholder mapping entry.
				loc.MappingIndex = getDummyMappingIndex(fileIDtoMapping, stringMap,
					profile, traceInfo.files[i])
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originated from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as a Line message:
				line := &profiles.Line{}

				fileIDInfoLock, exists := r.frames.Get(traceInfo.files[i])
				if !exists {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					line.FunctionIndex = createFunctionEntry(funcMap,
						"UNREPORTED", frameKind.String())
				} else {
					fileIDInfo := fileIDInfoLock.RLock()
					si, exists := (*fileIDInfo)[traceInfo.linenos[i]]
					if !exists {
						// At this point, we do not have enough information for the frame.
						// Therefore, we report a dummy entry and use the interpreter as filename.
						// To differentiate this case from the case where no information about
						// the file ID is available at all, we use a different name for reported
						// function.
						line.FunctionIndex = createFunctionEntry(funcMap,
							"UNRESOLVED", frameKind.String())
					} else {
						line.Line = int64(si.lineNumber)

						line.FunctionIndex = createFunctionEntry(funcMap,
							si.functionName, si.filePath)
					}
					fileIDInfoLock.RUnlock(&fileIDInfo)
				}
				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol, generate a dummy mapping entry.
				loc.MappingIndex = getDummyMappingIndex(fileIDtoMapping, stringMap,
					profile, traceInfo.files[i])
			}
			profile.Location = append(profile.Location, loc)
		}

		sample.Attributes = getSampleAttributes(profile, traceInfo)
		sample.LocationsLength = uint64(len(traceInfo.frameTypes))
		locationIndex += sample.LocationsLength

		profile.SampleType = append(profile.SampleType, setOnCPUValueType(stringMap))
		profile.Sample = append(profile.Sample, sample)
	}
	log.Debugf("Reporting OTLP profile with %d samples", len(profile.Sample))

	// Populate the deduplicated functions into profile.
	funcTable := make([]*profiles.Function, len(funcMap))
	for v, idx := range funcMap {
		funcTable[idx] = &profiles.Function{
			Name:     int64(getStringMapIndex(stringMap, v.name)),
			Filename: int64(getStringMapIndex(stringMap, v.fileName)),
		}
	}
	profile.Function = append(profile.Function, funcTable...)

	// When ranging over stringMap, the order will be according to the
	// hash value of the key. To get the correct order for profile.StringTable,
	// put the values in stringMap, in the correct array order.
	stringTable := make([]string, len(stringMap))
	for v, idx := range stringMap {
		stringTable[idx] = v
	}
	profile.StringTable = append(profile.StringTable, stringTable...)

	// profile.LocationIndices is not optional, and we only write elements into
	// profile.Location that at least one sample references.
	profile.LocationIndices = make([]int64, len(profile.Location))
	for i := int64(0); i < int64(len(profile.Location)); i++ {
		profile.LocationIndices[i] = i
	}

	profile.DurationNanos = int64(endTS - startTS)
	profile.TimeNanos = int64(startTS)

	return profile, startTS, endTS
}

// getStringMapIndex inserts or looks up the index for value in stringMap.
func getStringMapIndex(stringMap map[string]uint32, value string) uint32 {
	if idx, exists := stringMap[value]; exists {
		return idx
	}

	idx := uint32(len(stringMap))
	stringMap[value] = idx

	return idx
}

// createFunctionEntry adds a new function and returns its reference index.
func createFunctionEntry(funcMap map[funcInfo]uint64,
	name string, fileName string) uint64 {
	key := funcInfo{
		name:     name,
		fileName: fileName,
	}
	if idx, exists := funcMap[key]; exists {
		return idx
	}

	idx := uint64(len(funcMap))
	funcMap[key] = idx

	return idx
}

// getSampleAttributes builds a sample-specific list of attributes.
func getSampleAttributes(profile *profiles.Profile, i traceFramesCounts) []uint64 {
	indices := make([]uint64, 0, 4)

	addAttr := func(k attribute.Key, v string) {
		if v == "" {
			return
		}

		indices = append(indices, uint64(len(profile.AttributeTable)))
		profile.AttributeTable = append(profile.AttributeTable, &common.KeyValue{
			Key:   string(k),
			Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: v}},
		})
	}

	addAttr(semconv.K8SPodNameKey, i.podName)
	addAttr(semconv.ContainerNameKey, i.containerName)
	addAttr(semconv.ThreadNameKey, i.comm)
	addAttr(semconv.ServiceNameKey, i.apmServiceName)

	return indices
}

// getDummyMappingIndex inserts or looks up an entry for interpreted FileIDs.
func getDummyMappingIndex(fileIDtoMapping map[libpf.FileID]uint64,
	stringMap map[string]uint32, profile *profiles.Profile,
	fileID libpf.FileID) uint64 {
	var locationMappingIndex uint64
	if tmpMappingIndex, exists := fileIDtoMapping[fileID]; exists {
		locationMappingIndex = tmpMappingIndex
	} else {
		idx := uint64(len(fileIDtoMapping))
		fileIDtoMapping[fileID] = idx
		locationMappingIndex = idx

		profile.Mapping = append(profile.Mapping, &profiles.Mapping{
			Filename: int64(getStringMapIndex(stringMap, "")),
			BuildId: int64(getStringMapIndex(stringMap,
				fileID.StringNoQuotes())),
			BuildIdKind: *profiles.BuildIdKind_BUILD_ID_BINARY_HASH.Enum(),
		})
	}
	return locationMappingIndex
}

// setOnCPUValueType returns the default Profile.Sample_Type for on CPU profiling.
func setOnCPUValueType(stringMap map[string]uint32) *profiles.ValueType {
	return &profiles.ValueType{
		Type: int64(getStringMapIndex(stringMap, "on_cpu")),
		Unit: int64(getStringMapIndex(stringMap, "count")),
	}
}

// dedupSlice returns a sorted slice of unique values along with their count.
// If a value appears only a single time in values, its count will be 1,
// otherwise, count will be increased with every appearance of the same value.
// NOTE: This function may modify the input slice or return it as-is.
func dedupSlice(values []uint64) (out []uint64, count []int64) {
	if len(values) == 1 {
		return values, []int64{1}
	}

	out = make([]uint64, 0, len(values))
	count = make([]int64, 0, len(values))
	slices.Sort(values)

	for i := 0; i < len(values); i++ {
		if i > 0 && values[i-1] == values[i] {
			count[len(count)-1]++
			continue
		}
		out = append(out, values[i])
		count = append(count, 1)
	}
	return out, count
}

// waitGrpcEndpoint waits until the gRPC connection is established.
func waitGrpcEndpoint(ctx context.Context, cfg *Config,
	statsHandler *StatsHandlerImpl) (*grpc.ClientConn, error) {
	// Sleep with a fixed backoff time added of +/- 20% jitter
	tick := time.NewTicker(libpf.AddJitter(cfg.Times.GRPCStartupBackoffTime(), 0.2))
	defer tick.Stop()

	var retries uint32
	for {
		if collAgentConn, err := setupGrpcConnection(ctx, cfg, statsHandler); err != nil {
			if retries >= cfg.MaxGRPCRetries {
				return nil, err
			}
			retries++

			log.Warnf(
				"Failed to setup gRPC connection (try %d of %d): %v",
				retries,
				cfg.MaxGRPCRetries,
				err,
			)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-tick.C:
				continue
			}
		} else {
			return collAgentConn, nil
		}
	}
}

// setupGrpcConnection sets up a gRPC connection instrumented with our auth interceptor
func setupGrpcConnection(parent context.Context, cfg *Config,
	statsHandler *StatsHandlerImpl) (*grpc.ClientConn, error) {
	//nolint:staticcheck
	opts := []grpc.DialOption{grpc.WithBlock(),
		grpc.WithStatsHandler(statsHandler),
		grpc.WithUnaryInterceptor(cfg.GRPCClientInterceptor),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(cfg.MaxRPCMsgSize),
			grpc.MaxCallSendMsgSize(cfg.MaxRPCMsgSize)),
		grpc.WithReturnConnectionError(),
	}

	if cfg.DisableTLS {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		opts = append(opts,
			grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
				// Support only TLS1.3+ with valid CA certificates
				MinVersion:         tls.VersionTLS13,
				InsecureSkipVerify: false,
			})))
	}

	ctx, cancel := context.WithTimeout(parent, cfg.Times.GRPCConnectionTimeout())
	defer cancel()
	//nolint:staticcheck
	return grpc.DialContext(ctx, cfg.CollAgentAddr, opts...)
}
