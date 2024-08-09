/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"maps"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	lru "github.com/elastic/go-freelru"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/libpf/xsync"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/util"
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

var (
	cgroupv2PathPattern = regexp.MustCompile(`0:.*?:(.*)`)
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

// traceAndMetaKey is the deduplication key for samples. This **must always**
// contain all trace fields that aren't already part of the trace hash to ensure
// that we don't accidentally merge traces with different fields.
type traceAndMetaKey struct {
	hash libpf.TraceHash
	// comm and apmServiceName are provided by the eBPF programs
	comm           string
	apmServiceName string
	// containerID is annotated based on PID information
	containerID string
}

// traceFramesCounts holds known information about a trace.
type traceFramesCounts struct {
	files              []libpf.FileID
	linenos            []libpf.AddressOrLineno
	frameTypes         []libpf.FrameType
	mappingStarts      []libpf.Address
	mappingEnds        []libpf.Address
	mappingFileOffsets []uint64
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

	// cgroupv2ID caches PID to container ID information for cgroupv2 containers.
	cgroupv2ID *lru.SyncedLRU[util.PID, string]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[traceAndMetaKey]*traceFramesCounts]

	// pkgGRPCOperationTimeout sets the time limit for GRPC requests.
	pkgGRPCOperationTimeout time.Duration

	// samplesPerSecond is the number of samples per second.
	samplesPerSecond int

	// projectID is the project ID set by the user.
	projectID string

	// hostID is the unique identifier of the host.
	hostID string

	// kernelVersion is the version of the kernel.
	kernelVersion string

	// hostName is the name of the host.
	hostName string

	// ipAddress is the IP address of the host.
	ipAddress string
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
	timestamp libpf.UnixTime64, comm, apmServiceName string, pid util.PID) {
	traceEvents := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEvents)

	containerID, err := r.lookupCgroupv2(pid)
	if err != nil {
		log.Debugf("Failed to get a cgroupv2 ID as container ID for PID %d: %v",
			pid, err)
	}

	key := traceAndMetaKey{
		hash:           trace.Hash,
		comm:           comm,
		apmServiceName: apmServiceName,
		containerID:    containerID,
	}

	if tr, exists := (*traceEvents)[key]; exists {
		tr.timestamps = append(tr.timestamps, uint64(timestamp))
		(*traceEvents)[key] = tr
		return
	}

	(*traceEvents)[key] = &traceFramesCounts{
		files:              trace.Files,
		linenos:            trace.Linenos,
		frameTypes:         trace.FrameTypes,
		mappingStarts:      trace.MappingStart,
		mappingEnds:        trace.MappingEnd,
		mappingFileOffsets: trace.MappingFileOffsets,
		timestamps:         []uint64{uint64(timestamp)},
	}
}

// ReportFramesForTrace is a NOP for OTLPReporter.
func (r *OTLPReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for OTLPReporter.
func (r *OTLPReporter) ReportCountForTrace(_ libpf.TraceHash, _ libpf.UnixTime64,
	_ uint16, _, _ string, _ util.PID) {
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
func (r *OTLPReporter) ExecutableMetadata(_ context.Context, fileID libpf.FileID, fileName,
	buildID string, _ libpf.InterpreterType, _ ExecutableOpener) {
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
	mu := xsync.NewRWMutex(v)
	r.frames.Add(fileID, &mu)
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
	fallbackSymbols, err := lru.NewSynced[libpf.FrameID, string](cfg.CacheSize,
		libpf.FrameID.Hash32)
	if err != nil {
		return nil, err
	}

	executables, err := lru.NewSynced[libpf.FileID, execInfo](cfg.CacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		*xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]](cfg.CacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	cgroupv2ID, err := lru.NewSynced[util.PID, string](cfg.CacheSize,
		func(pid util.PID) uint32 { return uint32(pid) })
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

	r := &OTLPReporter{
		name:                    cfg.Name,
		version:                 cfg.Version,
		kernelVersion:           cfg.KernelVersion,
		hostName:                cfg.HostName,
		ipAddress:               cfg.IPAddress,
		samplesPerSecond:        cfg.SamplesPerSecond,
		hostID:                  strconv.FormatUint(cfg.HostID, 10),
		stopSignal:              make(chan libpf.Void),
		pkgGRPCOperationTimeout: cfg.GRPCOperationTimeout,
		client:                  nil,
		rpcStats:                NewStatsHandler(),
		fallbackSymbols:         fallbackSymbols,
		executables:             executables,
		frames:                  frames,
		hostmetadata:            hostmetadata,
		traceEvents:             xsync.NewRWMutex(map[traceAndMetaKey]*traceFramesCounts{}),
		cgroupv2ID:              cgroupv2ID,
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
		tick := time.NewTicker(cfg.ReportInterval)
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
				tick.Reset(libpf.AddJitter(cfg.ReportInterval, 0.2))
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
	addAttr("profiling.project.id", r.projectID)
	addAttr(semconv.HostIDKey, r.hostID)
	addAttr(semconv.HostIPKey, r.ipAddress)
	addAttr(semconv.HostNameKey, r.hostName)
	addAttr(semconv.ServiceVersionKey, r.version)
	addAttr("os.kernel", r.kernelVersion)

	return &resource.Resource{
		Attributes: attributes,
	}
}

// getProfile returns an OTLP profile containing all collected samples up to this moment.
func (r *OTLPReporter) getProfile() (profile *profiles.Profile, startTS, endTS uint64) {
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

	// attributeMap is a temporary helper that maps attribute values to
	// their respective indices.
	// This is to ensure that AttributeTable does not contain duplicates.
	attributeMap := make(map[string]uint64)

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
		Period: 1e9 / int64(r.samplesPerSecond),
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

	for traceKey, traceInfo := range samples {
		sample := &profiles.Sample{}
		sample.LocationsStartIndex = locationIndex

		sample.StacktraceIdIndex = getStringMapIndex(stringMap,
			traceKey.hash.Base64())

		slices.Sort(traceInfo.timestamps)
		startTS = traceInfo.timestamps[0]
		endTS = traceInfo.timestamps[len(traceInfo.timestamps)-1]

		sample.TimestampsUnixNano = traceInfo.timestamps
		sample.Value = []int64{1}

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

		sample.Attributes = getSampleAttributes(profile, traceKey, attributeMap)
		sample.LocationsLength = uint64(len(traceInfo.frameTypes))
		locationIndex += sample.LocationsLength

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
func getSampleAttributes(profile *profiles.Profile,
	k traceAndMetaKey, attributeMap map[string]uint64) []uint64 {
	indices := make([]uint64, 0, 4)

	addAttr := func(k attribute.Key, v string) {
		if v == "" {
			return
		}
		attributeCompositeKey := string(k) + "_" + v
		if attributeIndex, exists := attributeMap[attributeCompositeKey]; exists {
			indices = append(indices, attributeIndex)
			return
		}
		newIndex := uint64(len(profile.AttributeTable))
		indices = append(indices, newIndex)
		profile.AttributeTable = append(profile.AttributeTable, &common.KeyValue{
			Key:   string(k),
			Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: v}},
		})
		attributeMap[attributeCompositeKey] = newIndex
	}

	addAttr(semconv.ContainerIDKey, k.containerID)
	addAttr(semconv.ThreadNameKey, k.comm)
	addAttr(semconv.ServiceNameKey, k.apmServiceName)

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

// waitGrpcEndpoint waits until the gRPC connection is established.
func waitGrpcEndpoint(ctx context.Context, cfg *Config,
	statsHandler *StatsHandlerImpl) (*grpc.ClientConn, error) {
	// Sleep with a fixed backoff time added of +/- 20% jitter
	tick := time.NewTicker(libpf.AddJitter(cfg.GRPCStartupBackoffTime, 0.2))
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

	ctx, cancel := context.WithTimeout(parent, cfg.GRPCConnectionTimeout)
	defer cancel()
	//nolint:staticcheck
	return grpc.DialContext(ctx, cfg.CollAgentAddr, opts...)
}

// lookupCgroupv2 returns the cgroupv2 ID for pid.
func (r *OTLPReporter) lookupCgroupv2(pid util.PID) (string, error) {
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
