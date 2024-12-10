// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"maps"
	"strconv"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/pdata/pprofile"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*CollectorReporter)(nil)

// CollectorReporter receives and transforms information to be Collector Collector compliant.
type CollectorReporter struct {
	*BaseReporter

	nextConsumer consumerprofiles.Profiles

	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// runLoop handles the run loop
	runLoop *runLoop

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// hostID is the unique identifier of the host.
	hostID string

	// kernelVersion is the version of the kernel.
	kernelVersion string

	// hostName is the name of the host.
	hostName string

	// ipAddress is the IP address of the host.
	ipAddress string
}

// NewCollector builds a new CollectorReporter
func NewCollector(cfg *Config, nextConsumer consumerprofiles.Profiles) (*CollectorReporter, error) {
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

	return &CollectorReporter{
		BaseReporter: &BaseReporter{
			cfg:        cfg,
			pdata:      data,
			cgroupv2ID: cgroupv2ID,
			traceEvents: xsync.NewRWMutex(
				map[samples.TraceAndMetaKey]*samples.TraceEvents{},
			),
		},
		nextConsumer:  nextConsumer,
		name:          cfg.Name,
		version:       cfg.Version,
		kernelVersion: cfg.KernelVersion,
		hostName:      cfg.HostName,
		ipAddress:     cfg.IPAddress,
		hostID:        strconv.FormatUint(cfg.HostID, 10),
		runLoop: &runLoop{
			stopSignal: make(chan libpf.Void),
		},
		hostmetadata: hostmetadata,
	}, nil
}

func (r *CollectorReporter) Start(ctx context.Context) error {
	// Create a child context for reporting features
	ctx, cancelReporting := context.WithCancel(ctx)

	r.runLoop.Start(ctx, r.cfg.ReportInterval, func() {
		if err := r.reportProfile(context.Background()); err != nil {
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
	}()

	return nil
}

// ExecutableKnown returns true if the metadata of the Executable specified by fileID is
// cached in the reporter.
func (r *CollectorReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := r.pdata.Executables.GetAndRefresh(fileID, pdata.ExecutableCacheLifetime)
	return known
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (r *CollectorReporter) ExecutableMetadata(args *ExecutableMetadataArgs) {
	r.pdata.Executables.Add(args.FileID, samples.ExecInfo{
		FileName:   args.FileName,
		GnuBuildID: args.GnuBuildID,
	})
}

// FrameKnown return true if the metadata of the Frame specified by frameID is
// cached in the reporter.
func (r *CollectorReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := r.pdata.Frames.GetAndRefresh(frameID.FileID(),
		pdata.FramesCacheLifetime); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		_, known = (*frameMap)[frameID.AddressOrLine()]
	}
	return known
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
	r.runLoop.Stop()
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

// reportProfile creates and sends out a profile.
func (r *CollectorReporter) reportProfile(ctx context.Context) error {
	traceEvents := r.traceEvents.WLock()
	events := maps.Clone(*traceEvents)
	clear(*traceEvents)
	r.traceEvents.WUnlock(&traceEvents)

	profiles := r.pdata.Generate(events)
	for i := 0; i < profiles.ResourceProfiles().Len(); i++ {
		r.setResource(profiles.ResourceProfiles().At(i))
	}

	if profiles.SampleCount() == 0 {
		log.Debugf("Skip sending profile with no samples")
		return nil
	}

	return r.nextConsumer.ConsumeProfiles(ctx, profiles)
}

// setResource sets the resource information of the origin of the profiles.
// Next step: maybe extend this information with go.opentelemetry.io/otel/sdk/resource.
func (r *CollectorReporter) setResource(rp pprofile.ResourceProfiles) {
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
