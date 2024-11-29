// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"crypto/tls"
	"maps"
	"strconv"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*OTLPReporter)(nil)

// OTLPReporter receives and transforms information to be OTLP/profiles compliant.
type OTLPReporter struct {
	config *Config
	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// client for the connection to the receiver.
	client pprofileotlp.GRPCClient

	// runLoop handles the run loop
	runLoop *runLoop

	// rpcStats stores gRPC related statistics.
	rpcStats *StatsHandlerImpl

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long-term storage information that might
	// be duplicated in other places but not accessible for OTLPReporter.

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// cgroupv2ID caches PID to container ID information for cgroupv2 containers.
	cgroupv2ID *lru.SyncedLRU[libpf.PID, string]

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[samples.TraceAndMetaKey]*samples.TraceEvents]

	// pkgGRPCOperationTimeout sets the time limit for GRPC requests.
	pkgGRPCOperationTimeout time.Duration

	// hostID is the unique identifier of the host.
	hostID string

	// kernelVersion is the version of the kernel.
	kernelVersion string

	// hostName is the name of the host.
	hostName string

	// ipAddress is the IP address of the host.
	ipAddress string
}

// NewOTLP returns a new instance of OTLPReporter
func NewOTLP(cfg *Config) (*OTLPReporter, error) {
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

	data, err := pdata.New(
		cfg.SamplesPerSecond,
		cfg.ExecutablesCacheElements,
		cfg.FramesCacheElements,
	)
	if err != nil {
		return nil, err
	}

	return &OTLPReporter{
		config:        cfg,
		name:          cfg.Name,
		version:       cfg.Version,
		kernelVersion: cfg.KernelVersion,
		hostName:      cfg.HostName,
		ipAddress:     cfg.IPAddress,
		hostID:        strconv.FormatUint(cfg.HostID, 10),
		runLoop: &runLoop{
			stopSignal: make(chan libpf.Void),
		},
		pkgGRPCOperationTimeout: cfg.GRPCOperationTimeout,
		client:                  nil,
		rpcStats:                NewStatsHandler(),
		pdata:                   data,
		hostmetadata:            hostmetadata,
		traceEvents: xsync.NewRWMutex(
			map[samples.TraceAndMetaKey]*samples.TraceEvents{},
		),
		cgroupv2ID: cgroupv2ID,
	}, nil
}

// hashString is a helper function for LRUs that use string as a key.
// Xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

func (r *OTLPReporter) SupportsReportTraceEvent() bool { return true }

// ReportTraceEvent enqueues reported trace events for the OTLP reporter.
func (r *OTLPReporter) ReportTraceEvent(trace *libpf.Trace, meta *TraceEventMeta) {
	traceEventsMap := r.traceEvents.WLock()
	defer r.traceEvents.WUnlock(&traceEventsMap)

	containerID, err := libpf.LookupCgroupv2(r.cgroupv2ID, meta.PID)
	if err != nil {
		log.Debugf("Failed to get a cgroupv2 ID as container ID for PID %d: %v",
			meta.PID, err)
	}

	key := samples.TraceAndMetaKey{
		Hash:           trace.Hash,
		Comm:           meta.Comm,
		ApmServiceName: meta.APMServiceName,
		ContainerID:    containerID,
		Pid:            int64(meta.PID),
	}

	if events, exists := (*traceEventsMap)[key]; exists {
		events.Timestamps = append(events.Timestamps, uint64(meta.Timestamp))
		(*traceEventsMap)[key] = events
		return
	}

	(*traceEventsMap)[key] = &samples.TraceEvents{
		Files:              trace.Files,
		Linenos:            trace.Linenos,
		FrameTypes:         trace.FrameTypes,
		MappingStarts:      trace.MappingStart,
		MappingEnds:        trace.MappingEnd,
		MappingFileOffsets: trace.MappingFileOffsets,
		Timestamps:         []uint64{uint64(meta.Timestamp)},
	}
}

// ReportFramesForTrace is a NOP for OTLPReporter.
func (r *OTLPReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP for OTLPReporter.
func (r *OTLPReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *TraceEventMeta) {
}

// ExecutableKnown returns true if the metadata of the Executable specified by fileID is
// cached in the reporter.
func (r *OTLPReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := r.pdata.Executables.GetAndRefresh(fileID, ...)
	return known
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *OTLPReporter) ExecutableMetadata(args *ExecutableMetadataArgs) {
	r.pdata.Executables.Add(args.FileID, samples.ExecInfo{
		FileName:   args.FileName,
		GnuBuildID: args.GnuBuildID,
	})
}

// FrameKnown returns true if the metadata of the Frame specified by frameID is
// cached in the reporter.
func (r *OTLPReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := r.pdata.Frames.GetAndRefresh(frameID.FileID(), ...); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		_, known = (*frameMap)[frameID.AddressOrLine()]
	}
	return known
}

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (r *OTLPReporter) FrameMetadata(args *FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()

	log.Debugf("FrameMetadata [%x] %v+%v at %v:%v",
		fileID, args.FunctionName, args.FunctionOffset,
		args.SourceFile, args.SourceLine)

	if frameMapLock, exists := r.pdata.Frames.Get(fileID); exists {
		frameMap := frameMapLock.WLock()
		defer frameMapLock.WUnlock(&frameMap)

		sourceFile := args.SourceFile
		if sourceFile == "" {
			// The new SourceFile may be empty, and we don't want to overwrite
			// an existing filePath with it.
			if s, exists := (*frameMap)[addressOrLine]; exists {
				sourceFile = s.FilePath
			}
		}

		(*frameMap)[addressOrLine] = samples.SourceInfo{
			LineNumber:     args.SourceLine,
			FilePath:       sourceFile,
			FunctionOffset: args.FunctionOffset,
			FunctionName:   args.FunctionName,
		}
		return
	}

	v := make(map[libpf.AddressOrLineno]samples.SourceInfo)
	v[addressOrLine] = samples.SourceInfo{
		LineNumber:     args.SourceLine,
		FilePath:       args.SourceFile,
		FunctionOffset: args.FunctionOffset,
		FunctionName:   args.FunctionName,
	}
	mu := xsync.NewRWMutex(v)
	r.pdata.Frames.Add(fileID, &mu)
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
	r.runLoop.Stop()
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
func (r *OTLPReporter) Start(ctx context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(ctx)

	// Establish the gRPC connection before going on, waiting for a response
	// from the collectionAgent endpoint.
	// Use grpc.WithBlock() in setupGrpcConnection() for this to work.
	otlpGrpcConn, err := waitGrpcEndpoint(ctx, r.config, r.rpcStats)
	if err != nil {
		cancelReporting()
		r.runLoop.Stop()
		return err
	}
	r.client = pprofileotlp.NewGRPCClient(otlpGrpcConn)

	r.runLoop.Start(ctx, r.config.ReportInterval, func() {
		if err := r.reportOTLPProfile(ctx); err != nil {
			log.Errorf("Request failed: %v", err)
		}
	}, func() {
		// Allow the GC to purge expired entries to avoid memory leaks.
		r.pdata.Purge()
		r.cgroupv2ID.PurgeExpired()
	})

	// When Stop() is called and a signal to 'stop' is received, then:
	// - cancel the reporting functions currently running (using context)
	// - close the gRPC connection with collection-agent
	go func() {
		<-r.runLoop.stopSignal
		cancelReporting()
		if err := otlpGrpcConn.Close(); err != nil {
			log.Fatalf("Stopping connection of OTLP client client failed: %v", err)
		}
	}()

	return nil
}

// reportOTLPProfile creates and sends out an OTLP profile.
func (r *OTLPReporter) reportOTLPProfile(ctx context.Context) error {
	traceEvents := r.traceEvents.WLock()
	events := maps.Clone(*traceEvents)
	clear(*traceEvents)
	r.traceEvents.WUnlock(&traceEvents)

	profiles := r.pdata.Generate(events)
	for i := 0; i < profiles.ResourceProfiles().Len(); i++ {
		r.setResource(profiles.ResourceProfiles().At(i))
	}

	if profiles.SampleCount() == 0 {
		log.Debugf("Skip sending of OTLP profile with no samples")
		return nil
	}
	req := pprofileotlp.NewExportRequestFromProfiles(profiles)

	reqCtx, ctxCancel := context.WithTimeout(ctx, r.pkgGRPCOperationTimeout)
	defer ctxCancel()
	_, err := r.client.Export(reqCtx, req)
	return err
}

// setResource sets the resource information of the origin of the profiles.
// Next step: maybe extend this information with go.opentelemetry.io/otel/sdk/resource.
func (r *OTLPReporter) setResource(rp pprofile.ResourceProfiles) {
	keys := r.hostmetadata.Keys()
	attrs := rp.Resource().Attributes()

	// Add hostmedata to the attributes.
	for _, k := range keys {
		if v, ok := r.hostmetadata.Get(k); ok {
			attrs.PutStr(k, v)
		}
	}

	// Add event specific attributes.
	// These attributes are also included in the host metadata, but with different names/keys.
	// That makes our hostmetadata attributes incompatible with OTEL collectors.
	attrs.PutStr(string(semconv.HostIDKey), r.hostID)
	attrs.PutStr(string(semconv.HostIPKey), r.ipAddress)
	attrs.PutStr(string(semconv.HostNameKey), r.hostName)
	attrs.PutStr(string(semconv.ServiceVersionKey), r.version)
	attrs.PutStr("os.kernel", r.kernelVersion)
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
