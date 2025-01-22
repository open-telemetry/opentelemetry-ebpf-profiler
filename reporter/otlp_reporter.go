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
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/collector/pdata/pprofile/pprofileotlp"
	semconv "go.opentelemetry.io/otel/semconv/v1.22.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*OTLPReporter)(nil)

// OTLPReporter receives and transforms information to be OTLP/profiles compliant.
type OTLPReporter struct {
	*baseReporter

	// hostID is the unique identifier of the host.
	hostID string

	// kernelVersion is the version of the kernel.
	kernelVersion string

	// hostName is the name of the host.
	hostName string

	// ipAddress is the IP address of the host.
	ipAddress string

	// client for the connection to the receiver.
	client pprofileotlp.GRPCClient

	// rpcStats stores gRPC related statistics.
	rpcStats *StatsHandlerImpl

	// To fill in the OTLP/profiles signal with the relevant information,
	// this structure holds in long-term storage information that might
	// be duplicated in other places but not accessible for OTLPReporter.

	// pkgGRPCOperationTimeout sets the time limit for GRPC requests.
	pkgGRPCOperationTimeout time.Duration
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
		cfg.ExtraSampleAttrProd,
	)
	if err != nil {
		return nil, err
	}

	originsMap := make(map[libpf.Origin]samples.KeyToEventMapping, 2)
	for _, origin := range []libpf.Origin{support.TraceOriginSampling,
		support.TraceOriginOffCPU} {
		originsMap[origin] = make(samples.KeyToEventMapping)
	}

	return &OTLPReporter{
		baseReporter: &baseReporter{
			cfg:          cfg,
			name:         cfg.Name,
			version:      cfg.Version,
			pdata:        data,
			cgroupv2ID:   cgroupv2ID,
			traceEvents:  xsync.NewRWMutex(originsMap),
			hostmetadata: hostmetadata,
			runLoop: &runLoop{
				stopSignal: make(chan libpf.Void),
			},
		},
		kernelVersion:           cfg.KernelVersion,
		hostName:                cfg.HostName,
		ipAddress:               cfg.IPAddress,
		hostID:                  strconv.FormatUint(cfg.HostID, 10),
		pkgGRPCOperationTimeout: cfg.GRPCOperationTimeout,
		client:                  nil,
		rpcStats:                NewStatsHandler(),
	}, nil
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
	otlpGrpcConn, err := waitGrpcEndpoint(ctx, r.cfg, r.rpcStats)
	if err != nil {
		cancelReporting()
		r.runLoop.Stop()
		return err
	}
	r.client = pprofileotlp.NewGRPCClient(otlpGrpcConn)

	r.runLoop.Start(ctx, r.cfg.ReportInterval, func() {
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
	events := make(map[libpf.Origin]samples.KeyToEventMapping, 2)
	for _, origin := range []libpf.Origin{support.TraceOriginSampling,
		support.TraceOriginOffCPU} {
		events[origin] = maps.Clone((*traceEvents)[origin])
		clear((*traceEvents)[origin])
	}
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
