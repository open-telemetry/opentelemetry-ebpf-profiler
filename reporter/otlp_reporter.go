/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/libpf/vc"
	otlpcollector "github.com/elastic/otel-profiling-agent/proto/experiments/opentelemetry/proto/collector/profiles/v1"
	profiles "github.com/elastic/otel-profiling-agent/proto/experiments/opentelemetry/proto/profiles/v1"
	"github.com/elastic/otel-profiling-agent/proto/experiments/opentelemetry/proto/profiles/v1/alternatives/pprofextended"

	"github.com/elastic/otel-profiling-agent/debug/log"
	"github.com/elastic/otel-profiling-agent/libpf"

	common "go.opentelemetry.io/proto/otlp/common/v1"
	resource "go.opentelemetry.io/proto/otlp/resource/v1"

	lru "github.com/elastic/go-freelru"
	"github.com/zeebo/xxh3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/encoding/gzip"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*OTLPReporter)(nil)

// traceInfo holds static information about a trace.
type traceInfo struct {
	files          []libpf.FileID
	linenos        []libpf.AddressOrLineno
	frameTypes     []libpf.FrameType
	comm           string
	podName        string
	containerName  string
	apmServiceName string
}

// sample holds dynamic information about traces.
type sample struct {
	// In most cases OTEP/profiles requests timestamps in a uint64 format
	// and use nanosecond precision - https://github.com/open-telemetry/oteps/issues/253
	timestamps []uint64
	count      uint32
}

// execInfo enriches an executable with additional metadata.
type execInfo struct {
	fileName string
	buildID  string
}

// sourceInfo allows to map a frame to its source origin.
type sourceInfo struct {
	lineNumber     libpf.SourceLineno
	functionOffset uint32
	functionName   string
	filePath       string
}

// funcInfo is a helper to construct profile.Function messages.
type funcInfo struct {
	name     string
	fileName string
}

// OTLPReporter receives and transforms information to be OTLP/profiles compliant.
type OTLPReporter struct {
	// client for the connection to the receiver.
	client otlpcollector.ProfilesServiceClient

	// stopSignal is the stop signal for shutting down all background tasks.
	stopSignal chan libpf.Void

	// rpcStats stores gRPC related statistics.
	rpcStats *statsHandlerImpl

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long term storage information that might
	// be duplicated in other places but not accessible for OTLPReporter.

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// traces stores static information needed for samples.
	traces *lru.SyncedLRU[libpf.TraceHash, traceInfo]

	// samples holds a map of currently encountered traces.
	samples *lru.SyncedLRU[libpf.TraceHash, sample]

	// fallbackSymbols keeps track of FrameID to their symbol.
	fallbackSymbols *lru.SyncedLRU[libpf.FrameID, string]

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, execInfo]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, map[libpf.AddressOrLineno]sourceInfo]
}

// hashString is a helper function for LRUs that use string as a key.
// xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

// ReportFramesForTrace accepts a trace with the corresponding frames
// and caches this information.
func (r *OTLPReporter) ReportFramesForTrace(trace *libpf.Trace) {
	if v, exists := r.traces.Peek(trace.Hash); exists {
		// As traces is filled from two different API endpoints,
		// some information for the trace might be available already.
		// For simplicty, the just received information overwrites the
		// the existing one.
		v.files = trace.Files
		v.linenos = trace.Linenos
		v.frameTypes = trace.FrameTypes

		r.traces.Add(trace.Hash, v)
	} else {
		r.traces.Add(trace.Hash, traceInfo{
			files:      trace.Files,
			linenos:    trace.Linenos,
			frameTypes: trace.FrameTypes,
		})
	}
}

// ReportCountForTrace accepts a hash of a trace with a corresponding count and
// caches this information.
func (r *OTLPReporter) ReportCountForTrace(traceHash libpf.TraceHash, timestamp libpf.UnixTime32,
	count uint16, comm, podName, containerName string) {
	if v, exists := r.traces.Peek(traceHash); exists {
		// As traces is filled from two different API endpoints,
		// some information for the trace might be available already.
		// For simplicty, the just received information overwrites the
		// the existing one.
		v.comm = comm
		v.podName = podName
		v.containerName = containerName

		r.traces.Add(traceHash, v)
	} else {
		r.traces.Add(traceHash, traceInfo{
			comm:          comm,
			podName:       podName,
			containerName: containerName,
		})
	}

	if v, ok := r.samples.Peek(traceHash); ok {
		v.count += uint32(count)
		v.timestamps = append(v.timestamps, uint64(timestamp))

		r.samples.Add(traceHash, v)
	} else {
		r.samples.Add(traceHash, sample{
			count:      uint32(count),
			timestamps: []uint64{uint64(timestamp)},
		})
	}
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
	lineNumber libpf.SourceLineno, functionOffset uint32, functionName, filePath string) {
	if v, exists := r.frames.Get(fileID); exists {
		if filePath == "" {
			// The new filePath may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := v[addressOrLine]; exists {
				filePath = s.filePath
			}
		}
		v[addressOrLine] = sourceInfo{
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
	r.frames.Add(fileID, v)
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
		RPCBytesOutCount:  r.rpcStats.getRPCBytesOut(),
		RPCBytesInCount:   r.rpcStats.getRPCBytesIn(),
		WireBytesOutCount: r.rpcStats.getWireBytesOut(),
		WireBytesInCount:  r.rpcStats.getWireBytesIn(),
	}
}

const rpcPrefix = "/opentelemetry.proto.collector.profiles.v1.ProfilesService/Export"

// LogMetrics logs internal metrics of OTLPReporter.
func (r *OTLPReporter) LogMetrics() {
	methodOut := r.rpcStats.getMethodRPCBytesOut()
	methodWireOut := r.rpcStats.getMethodWireBytesOut()

	rpcBytes := map[string]uint64{}

	for name, numBytes := range methodOut {
		if strings.HasPrefix(name, rpcPrefix) {
			rpcBytes[name] = numBytes
		}
	}

	// Consistent ordering
	keys := libpf.MapKeysToSlice(methodWireOut)
	sort.Strings(keys)

	for _, name := range keys {
		if strings.HasPrefix(name, rpcPrefix) {
			log.Warnf("Bytes: %v WireBytes: %v [%v]",
				rpcBytes[name], methodWireOut[name],
				name[strings.LastIndex(name, "/")+1:])
		}
	}

	log.Warnf("")
}

// StartOTLP sets up and manages the reporting connection to a OTLP backend.
func StartOTLP(mainCtx context.Context, c *Config) (Reporter, error) {
	cacheSize := config.TraceCacheEntries()

	traces, err := lru.NewSynced[libpf.TraceHash, traceInfo](cacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	samples, err := lru.NewSynced[libpf.TraceHash, sample](cacheSize, libpf.TraceHash.Hash32)
	if err != nil {
		return nil, err
	}

	fallbackSymbols, err := lru.NewSynced[libpf.FrameID, string](cacheSize, libpf.FrameID.Hash32)
	if err != nil {
		return nil, err
	}

	executables, err := lru.NewSynced[libpf.FileID, execInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	frames, err := lru.NewSynced[libpf.FileID,
		map[libpf.AddressOrLineno]sourceInfo](cacheSize, libpf.FileID.Hash32)
	if err != nil {
		return nil, err
	}

	// Next step: Dynamically configure the size of this LRU.
	// Currently we use the length of the JSON array in
	// hostmetadata/hostmetadata.json.
	hostmetadata, err := lru.NewSynced[string, string](115, hashString)
	if err != nil {
		return nil, err
	}

	r := &OTLPReporter{
		stopSignal:      make(chan libpf.Void),
		client:          nil,
		rpcStats:        newStatsHandler(),
		traces:          traces,
		samples:         samples,
		fallbackSymbols: fallbackSymbols,
		executables:     executables,
		frames:          frames,
		hostmetadata:    hostmetadata,
	}

	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(mainCtx)

	// Establish the gRPC connection before going on, waiting for a response
	// from the collectionAgent endpoint.
	// Use grpc.WithBlock() in setupGrpcConnection() for this to work.
	otlpGrpcConn, err := waitGrpcEndpoint(ctx, c, r.rpcStats)
	if err != nil {
		cancelReporting()
		close(r.stopSignal)
		return nil, err
	}
	r.client = otlpcollector.NewProfilesServiceClient(otlpGrpcConn)

	go func() {
		tick := time.NewTicker(c.Times.ReportInterval())
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
				tick.Reset(libpf.AddJitter(c.Times.ReportInterval(), 0.2))
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
	profile, startTS, endTS, samples := r.getProfile()

	if len(profile.Sample) == 0 {
		log.Debugf("Skip sending of OTLP profile with no samples")
		return nil
	}

	profileStacks, _, _ := r.getProfileStacks(samples)

	pc := []*profiles.ProfileContainer{{
		// Next step: not sure about the value of ProfileId
		// Discussion around this field and its requirements started with
		// https://github.com/open-telemetry/oteps/pull/239#discussion_r1491546899
		// As an ID with all zeros is considered invalid, we write ELASTIC here.
		ProfileId:         []byte("ELASTIC"),
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
			Name:    "Elastic-Universal-Profiling",
			Version: fmt.Sprintf("%s@%s", vc.Version(), vc.Revision()),
		},
		// SchemaUrl - This element is not well defined yet. Therefore we skip it.
	}}

	resourceProfiles := []*profiles.ResourceProfiles{{
		Resource:      r.getResource(),
		ScopeProfiles: scopeProfiles,
		// SchemaUrl - This element is not well defined yet. Therefore we skip it.
	}}

	req := otlpcollector.ExportProfilesServiceRequest{
		ResourceProfiles: resourceProfiles,
	}

	gzipOption := grpc.UseCompressor(gzip.Name)

	// Base RPC (no proto changes)
	_, err := r.client.Export(ctx, &req, gzipOption)

	// Delta timestamps
	for _, s := range profile.Sample {
		for idx, v := range s.Timestamps {
			s.Timestamps[idx] = v - startTS
			//			log.Warnf("DD: %v", s.Timestamps[idx])
		}
	}
	_, err = r.client.ExportDeltaTime(ctx, &req, gzipOption)

	// Zero-out timestamps
	for _, s := range profile.Sample {
		for idx, _ := range s.Timestamps {
			//			log.Warnf("TT: %v", time.Unix(0, int64(s.Timestamps[idx])))
			s.Timestamps[idx] = 0
		}
	}
	_, err = r.client.ExportZeroTime(ctx, &req, gzipOption)

	// Alternate stack representation
	req.ResourceProfiles[0].ScopeProfiles[0].Profiles[0].Profile = profileStacks
	_, err = r.client.ExportStacks(ctx, &req, gzipOption)

	r.LogMetrics()
	return err
}

// getResource returns the OTLP resource information of the origin of the profiles.
// Next step: maybe extend this information with go.opentelemetry.io/otel/sdk/resource.
func (r *OTLPReporter) getResource() *resource.Resource {
	keys := r.hostmetadata.Keys()

	attributes := make([]*common.KeyValue, len(keys))
	i := 0
	for _, k := range keys {
		v, ok := r.hostmetadata.Get(k)
		if !ok {
			continue
		}
		attributes[i] = &common.KeyValue{
			Key:   k,
			Value: &common.AnyValue{Value: &common.AnyValue_StringValue{StringValue: v}},
		}
		i++
	}
	origin := &resource.Resource{
		Attributes: attributes,
	}
	return origin
}

// getProfile returns an OTLP profile containing all collected samples up to this moment.
func (r *OTLPReporter) getProfile() (profile *pprofextended.Profile, startTS uint64, endTS uint64,
	samples map[libpf.TraceHash]sample) {
	// Avoid overlapping locks by copying its content.
	sampleKeys := r.samples.Keys()
	samplesCpy := make(map[libpf.TraceHash]sample, len(sampleKeys))
	for _, k := range sampleKeys {
		v, ok := r.samples.Get(k)
		if !ok {
			continue
		}
		samplesCpy[k] = v
		r.samples.Remove(k)
	}

	var samplesWoTraceinfo []libpf.TraceHash

	for trace := range samplesCpy {
		if _, exists := r.traces.Peek(trace); !exists {
			samplesWoTraceinfo = append(samplesWoTraceinfo, trace)
		}
	}

	if len(samplesWoTraceinfo) != 0 {
		log.Debugf("Missing trace information for %d samples", len(samplesWoTraceinfo))
		// Return samples for which relevant information is not available yet.
		for _, trace := range samplesWoTraceinfo {
			r.samples.Add(trace, samplesCpy[trace])
			delete(samplesCpy, trace)
		}
	}

	// stringMap is a temporary helper that will build the StringTable.
	// By specification, the first element should be empty.
	stringMap := make(map[string]uint32)
	stringMap[""] = 0

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]uint64)
	funcMap[funcInfo{name: "", fileName: ""}] = 0

	numSamples := len(samplesCpy)
	profile = &pprofextended.Profile{
		// SampleType - Next step: Figure out the correct SampleType.
		Sample: make([]*pprofextended.Sample, 0, numSamples),
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

	if numSamples == 0 {
		return
	}

	locationIndex := uint64(0)

	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]uint64)
	frameIDtoFunction := make(map[libpf.FrameID]uint64)

	for traceHash, sampleInfo := range samplesCpy {
		sample := &pprofextended.Sample{}
		sample.LocationsStartIndex = locationIndex

		// Earlier we peeked into traces for traceHash and know it exists.
		trace, _ := r.traces.Get(traceHash)

		sample.Timestamps = make([]uint64, 0, len(sampleInfo.timestamps))
		for _, ts := range sampleInfo.timestamps {
			sample.Timestamps = append(sample.Timestamps, uint64(ts))
			if ts < startTS || startTS == 0 {
				startTS = ts
				continue
			}
			if ts > endTS {
				endTS = ts
			}
		}

		// Walk every frame of the trace.
		for i := range trace.frameTypes {
			loc := &pprofextended.Location{
				// Id - Optional element we do not use.
				TypeIndex: getStringMapIndex(stringMap,
					trace.frameTypes[i].String()),
				Address: uint64(trace.linenos[i]),
				// IsFolded - Optional element we do not use.
				// Attributes - Optional element we do not use.
			}

			switch frameKind := trace.frameTypes[i]; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.

				var locationMappingIndex uint64
				if tmpMappingIndex, exists := fileIDtoMapping[trace.files[i]]; exists {
					locationMappingIndex = tmpMappingIndex
				} else {
					idx := uint64(len(fileIDtoMapping))
					fileIDtoMapping[trace.files[i]] = idx
					locationMappingIndex = idx

					execInfo, exists := r.executables.Get(trace.files[i])

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = "UNKNOWN"
					if exists {
						fileName = execInfo.fileName
					}

					profile.Mapping = append(profile.Mapping, &pprofextended.Mapping{
						// Id - Optional element we do not use.
						// MemoryStart - Optional element we do not use.
						// MemoryLImit - Optional element we do not use.
						FileOffset: uint64(trace.linenos[i]),
						Filename:   int64(getStringMapIndex(stringMap, fileName)),
						BuildId: int64(getStringMapIndex(stringMap,
							trace.files[i].StringNoQuotes())),
						BuildIdKind: *pprofextended.BuildIdKind_BUILD_ID_BINARY_HASH.Enum(),
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
				frameID := libpf.NewFrameID(trace.files[i], trace.linenos[i])
				// Store Kernel frame information as Line message:
				line := &pprofextended.Line{}

				if tmpFunctionIndex, exists := frameIDtoFunction[frameID]; exists {
					line.FunctionIndex = tmpFunctionIndex
				} else {
					symbol, exists := r.fallbackSymbols.Get(frameID)
					if !exists {
						// TODO: choose a proper default value if the kernel symbol was not
						// reported yet.
						symbol = "UNKNOWN"
					}
					line.FunctionIndex = createFunctionEntry(funcMap,
						symbol, "vmlinux")
				}
				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol generate a dummy mapping entry.
				loc.MappingIndex = getDummyMappingIndex(fileIDtoMapping, stringMap,
					profile, trace.files[i])
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as Line message:
				line := &pprofextended.Line{}

				fileIDInfo, exists := r.frames.Get(trace.files[i])
				if !exists {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					line.FunctionIndex = createFunctionEntry(funcMap,
						"UNREPORTED", frameKind.String())
				} else {
					si, exists := fileIDInfo[trace.linenos[i]]
					if !exists {
						// At this point, we do not have enough information for the frame.
						// Therefore, we report a dummy entry and use the interpreter as filename.
						// To differentiate this case with the case where no information about
						// the file ID is available at all, we use a different name for reported
						// function.
						line.FunctionIndex = createFunctionEntry(funcMap,
							"UNRESOLVED", frameKind.String())
					} else {
						line.Line = int64(si.lineNumber)

						line.FunctionIndex = createFunctionEntry(funcMap,
							si.functionName, si.filePath)
					}
				}
				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol generate a dummy mapping entry.
				loc.MappingIndex = getDummyMappingIndex(fileIDtoMapping, stringMap,
					profile, trace.files[i])
			}
			profile.Location = append(profile.Location, loc)
		}

		sample.Label = getTraceLabels(stringMap, trace)
		sample.LocationsLength = uint64(len(trace.frameTypes))
		locationIndex += sample.LocationsLength

		profile.Sample = append(profile.Sample, sample)
	}
	log.Debugf("Reporting OTLP profile with %d samples", len(profile.Sample))

	// Populate the deduplicated functions into profile.
	funcTable := make([]*pprofextended.Function, len(funcMap))
	for v, idx := range funcMap {
		funcTable[idx] = &pprofextended.Function{
			Name:     int64(getStringMapIndex(stringMap, v.name)),
			Filename: int64(getStringMapIndex(stringMap, v.fileName)),
		}
	}
	profile.Function = append(profile.Function, funcTable...)

	// When ranging over stringMap the order will be according to the
	// hash value of the key. To get the correct order for profile.StringTable,
	// put the values in stringMap in the correct array order.
	stringTable := make([]string, len(stringMap))
	for v, idx := range stringMap {
		stringTable[idx] = v
	}
	profile.StringTable = append(profile.StringTable, stringTable...)

	// profile.LocationIndices is not optional and we only write elements into
	// profile.Location that are referenced by sample.
	profile.LocationIndices = make([]int64, len(profile.Location))
	for i := int64(0); i < int64(len(profile.Location)); i++ {
		profile.LocationIndices[i] = i
	}

	return profile, startTS, endTS, samplesCpy
}

// getProfile returns an OTLP profile containing all collected samples up to this moment.
func (r *OTLPReporter) getProfileStacks(samples map[libpf.TraceHash]sample) (profile *pprofextended.Profile, startTS uint64, endTS uint64) {
	// stringMap is a temporary helper that will build the StringTable.
	// By specification, the first element should be empty.
	stringMap := make(map[string]uint32)
	stringMap[""] = 0

	// funcMap is a temporary helper that will build the Function array
	// in profile and make sure information is deduplicated.
	funcMap := make(map[funcInfo]uint64)
	funcMap[funcInfo{name: "", fileName: ""}] = 0

	// Used to deduplicate Locations
	locationKeyMap := make(map[locationKey]uint32)

	// Used to deduplicate Stacks
	stackKeyMap := make(map[stackKey]uint32)

	numSamples := len(samples)
	profile = &pprofextended.Profile{
		// SampleType - Next step: Figure out the correct SampleType.
		Sample: make([]*pprofextended.Sample, 0, numSamples),
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

	// Temporary lookup to reference existing Mappings.
	fileIDtoMapping := make(map[libpf.FileID]uint64)
	frameIDtoFunction := make(map[libpf.FrameID]uint64)

	for traceHash, sampleInfo := range samples {
		sample := &pprofextended.Sample{}
		stack := &pprofextended.Stack{}

		// Earlier we peeked into traces for traceHash and know it exists.
		trace, _ := r.traces.Get(traceHash)

		sample.Timestamps = make([]uint64, 0, len(sampleInfo.timestamps))
		for _, ts := range sampleInfo.timestamps {
			sample.Timestamps = append(sample.Timestamps, uint64(ts))
			if ts < startTS || startTS == 0 {
				startTS = ts
				continue
			}
			if ts > endTS {
				endTS = ts
			}
		}

		// Walk every frame of the trace.
		for i := range trace.frameTypes {
			loc := &pprofextended.Location{
				// Id - Optional element we do not use.
				TypeIndex: getStringMapIndex(stringMap,
					trace.frameTypes[i].String()),
				Address: uint64(trace.linenos[i]),
				// IsFolded - Optional element we do not use.
				// Attributes - Optional element we do not use.
			}

			switch frameKind := trace.frameTypes[i]; frameKind {
			case libpf.NativeFrame:
				// As native frames are resolved in the backend, we use Mapping to
				// report these frames.

				var locationMappingIndex uint64
				if tmpMappingIndex, exists := fileIDtoMapping[trace.files[i]]; exists {
					locationMappingIndex = tmpMappingIndex
				} else {
					idx := uint64(len(fileIDtoMapping))
					fileIDtoMapping[trace.files[i]] = idx
					locationMappingIndex = idx

					execInfo, exists := r.executables.Get(trace.files[i])

					// Next step: Select a proper default value,
					// if the name of the executable is not known yet.
					var fileName = "UNKNOWN"
					if exists {
						fileName = execInfo.fileName
					}

					profile.Mapping = append(profile.Mapping, &pprofextended.Mapping{
						// Id - Optional element we do not use.
						// MemoryStart - Optional element we do not use.
						// MemoryLImit - Optional element we do not use.
						FileOffset: uint64(trace.linenos[i]),
						Filename:   int64(getStringMapIndex(stringMap, fileName)),
						BuildId: int64(getStringMapIndex(stringMap,
							trace.files[i].StringNoQuotes())),
						BuildIdKind: *pprofextended.BuildIdKind_BUILD_ID_BINARY_HASH.Enum(),
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
				frameID := libpf.NewFrameID(trace.files[i], trace.linenos[i])
				// Store Kernel frame information as Line message:
				line := &pprofextended.Line{}

				if tmpFunctionIndex, exists := frameIDtoFunction[frameID]; exists {
					line.FunctionIndex = tmpFunctionIndex
				} else {
					symbol, exists := r.fallbackSymbols.Get(frameID)
					if !exists {
						// TODO: choose a proper default value if the kernel symbol was not
						// reported yet.
						symbol = "UNKNOWN"
					}
					line.FunctionIndex = createFunctionEntry(funcMap,
						symbol, "vmlinux")
				}

				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol generate a dummy mapping entry.
				loc.MappingIndex = getDummyMappingIndex(fileIDtoMapping, stringMap,
					profile, trace.files[i])
			case libpf.AbortFrame:
				// Next step: Figure out how the OTLP protocol
				// could handle artificial frames, like AbortFrame,
				// that are not originate from a native or interpreted
				// program.
			default:
				// Store interpreted frame information as Line message:
				line := &pprofextended.Line{}

				fileIDInfo, exists := r.frames.Get(trace.files[i])
				if !exists {
					// At this point, we do not have enough information for the frame.
					// Therefore, we report a dummy entry and use the interpreter as filename.
					line.FunctionIndex = createFunctionEntry(funcMap,
						"UNREPORTED", frameKind.String())
				} else {
					si, exists := fileIDInfo[trace.linenos[i]]
					if !exists {
						// At this point, we do not have enough information for the frame.
						// Therefore, we report a dummy entry and use the interpreter as filename.
						// To differentiate this case with the case where no information about
						// the file ID is available at all, we use a different name for reported
						// function.
						line.FunctionIndex = createFunctionEntry(funcMap,
							"UNRESOLVED", frameKind.String())
					} else {
						line.Line = int64(si.lineNumber)

						line.FunctionIndex = createFunctionEntry(funcMap,
							si.functionName, si.filePath)
					}
				}
				loc.Line = append(loc.Line, line)

				// To be compliant with the protocol generate a dummy mapping entry.
				loc.MappingIndex = getDummyMappingIndex(fileIDtoMapping, stringMap,
					profile, trace.files[i])
			}

			// Deduplicate Location
			locKey := locationKey{
				typeIndex:    loc.TypeIndex,
				address:      loc.Address,
				mappingIndex: loc.MappingIndex,
				line:         fmt.Sprintf("%v", loc.Line),
			}

			locIdx, exists := getLocationIndex(locationKeyMap, locKey)
			if !exists {
				profile.Location = append(profile.Location, loc)
			}

			stack.LocationIndices = append(stack.LocationIndices, int32(locIdx))
		}

		// Deduplicate Stack
		stackKey := stackKey{
			locationIndices: fmt.Sprintf("%v", stack.LocationIndices),
		}
		stackIdx, exists := getStackIndex(stackKeyMap, stackKey)
		if !exists {
			profile.StackTable = append(profile.StackTable, stack)
		}
		sample.StackIndex = int32(stackIdx)

		sample.Label = getTraceLabels(stringMap, trace)
		profile.Sample = append(profile.Sample, sample)
	}

	log.Debugf("Reporting OTLP profile with %d samples", len(profile.Sample))

	// Populate the deduplicated functions into profile.
	funcTable := make([]*pprofextended.Function, len(funcMap))
	for v, idx := range funcMap {
		funcTable[idx] = &pprofextended.Function{
			Name:     int64(getStringMapIndex(stringMap, v.name)),
			Filename: int64(getStringMapIndex(stringMap, v.fileName)),
		}
	}
	profile.Function = append(profile.Function, funcTable...)

	// When ranging over stringMap the order will be according to the
	// hash value of the key. To get the correct order for profile.StringTable,
	// put the values in stringMap in the correct array order.
	stringTable := make([]string, len(stringMap))
	for v, idx := range stringMap {
		stringTable[idx] = v
	}
	profile.StringTable = append(profile.StringTable, stringTable...)

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

type locationKey struct {
	typeIndex    uint32
	address      uint64
	mappingIndex uint64
	line         string
}

type stackKey struct {
	locationIndices string
}

func getLocationIndex(locationKeyMap map[locationKey]uint32, value locationKey) (uint32, bool) {
	if idx, exists := locationKeyMap[value]; exists {
		return idx, true
	}

	idx := uint32(len(locationKeyMap))
	locationKeyMap[value] = idx
	return idx, false
}

func getStackIndex(stackKeyMap map[stackKey]uint32, value stackKey) (uint32, bool) {
	if idx, exists := stackKeyMap[value]; exists {
		return idx, true
	}

	idx := uint32(len(stackKeyMap))
	stackKeyMap[value] = idx
	return idx, false
}

// getTraceLabels builds OTEP/Label(s) from traceInfo.
func getTraceLabels(stringMap map[string]uint32, i traceInfo) []*pprofextended.Label {
	var labels []*pprofextended.Label

	if i.comm != "" {
		commIdx := getStringMapIndex(stringMap, "comm")
		commValueIdx := getStringMapIndex(stringMap, i.comm)

		labels = append(labels, &pprofextended.Label{
			Key: int64(commIdx),
			Str: int64(commValueIdx),
		})
	}

	if i.podName != "" {
		podNameIdx := getStringMapIndex(stringMap, "podName")
		podNameValueIdx := getStringMapIndex(stringMap, i.podName)

		labels = append(labels, &pprofextended.Label{
			Key: int64(podNameIdx),
			Str: int64(podNameValueIdx),
		})
	}

	if i.containerName != "" {
		containerNameIdx := getStringMapIndex(stringMap, "containerName")
		containerNameValueIdx := getStringMapIndex(stringMap, i.containerName)

		labels = append(labels, &pprofextended.Label{
			Key: int64(containerNameIdx),
			Str: int64(containerNameValueIdx),
		})
	}

	if i.apmServiceName != "" {
		apmServiceNameIdx := getStringMapIndex(stringMap, "apmServiceName")
		apmServiceNameValueIdx := getStringMapIndex(stringMap, i.apmServiceName)

		labels = append(labels, &pprofextended.Label{
			Key: int64(apmServiceNameIdx),
			Str: int64(apmServiceNameValueIdx),
		})
	}

	return labels
}

// getDummyMappingIndex inserts or looks up a dummy entry for interpreted FileIDs.
func getDummyMappingIndex(fileIDtoMapping map[libpf.FileID]uint64,
	stringMap map[string]uint32, profile *pprofextended.Profile,
	fileID libpf.FileID) uint64 {
	var locationMappingIndex uint64
	if tmpMappingIndex, exists := fileIDtoMapping[fileID]; exists {
		locationMappingIndex = tmpMappingIndex
	} else {
		idx := uint64(len(fileIDtoMapping))
		fileIDtoMapping[fileID] = idx
		locationMappingIndex = idx

		fileName := "DUMMY"

		profile.Mapping = append(profile.Mapping, &pprofextended.Mapping{
			Filename: int64(getStringMapIndex(stringMap, fileName)),
			BuildId: int64(getStringMapIndex(stringMap,
				fileID.StringNoQuotes())),
			BuildIdKind: *pprofextended.BuildIdKind_BUILD_ID_BINARY_HASH.Enum(),
		})
	}
	return locationMappingIndex
}
