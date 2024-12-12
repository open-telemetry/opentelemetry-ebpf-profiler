// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"time"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/collector/pdata/pprofile"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/pdata"
	"go.opentelemetry.io/ebpf-profiler/reporter/internal/samples"
	semconv "go.opentelemetry.io/otel/semconv/v1.25.0"
)

// baseReporter encapsulates shared behavior between all the available reporters.
type baseReporter struct {
	cfg *Config

	// name is the ScopeProfile's name.
	name string

	// version is the ScopeProfile's version.
	version string

	// hostID is the unique identifier of the host.
	hostID string

	// kernelVersion is the version of the kernel.
	kernelVersion string

	// hostName is the name of the host.
	hostName string

	// ipAddress is the IP address of the host.
	ipAddress string

	// runLoop handles the run loop
	runLoop *runLoop

	// pdata holds the generator for the data being exported.
	pdata *pdata.Pdata

	// cgroupv2ID caches PID to container ID information for cgroupv2 containers.
	cgroupv2ID *lru.SyncedLRU[libpf.PID, string]

	// traceEvents stores reported trace events (trace metadata with frames and counts)
	traceEvents xsync.RWMutex[map[samples.TraceAndMetaKey]*samples.TraceEvents]

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]
}

func (b *BaseReporter) Stop() {
	b.runLoop.Stop()
}

func (b *BaseReporter) ReportHostMetadata(metadataMap map[string]string) {
	b.addHostmetadata(metadataMap)
}

func (b *BaseReporter) ReportHostMetadataBlocking(_ context.Context,
	metadataMap map[string]string, _ int, _ time.Duration) error {
	b.addHostmetadata(metadataMap)
	return nil
}

// addHostmetadata adds to and overwrites host metadata.
func (b *BaseReporter) addHostmetadata(metadataMap map[string]string) {
	for k, v := range metadataMap {
		b.hostmetadata.Add(k, v)
	}
}

// ReportFramesForTrace is a NOP
func (*BaseReporter) ReportFramesForTrace(_ *libpf.Trace) {}

// ReportCountForTrace is a NOP
func (b *BaseReporter) ReportCountForTrace(_ libpf.TraceHash, _ uint16, _ *TraceEventMeta) {
}

func (b *BaseReporter) ExecutableKnown(fileID libpf.FileID) bool {
	_, known := b.pdata.Executables.GetAndRefresh(fileID, pdata.ExecutableCacheLifetime)
	return known
}

func (b *BaseReporter) FrameKnown(frameID libpf.FrameID) bool {
	known := false
	if frameMapLock, exists := b.pdata.Frames.GetAndRefresh(frameID.FileID(),
		pdata.FramesCacheLifetime); exists {
		frameMap := frameMapLock.RLock()
		defer frameMapLock.RUnlock(&frameMap)
		_, known = (*frameMap)[frameID.AddressOrLine()]
	}
	return known
}

// ExecutableMetadata accepts a fileID with the corresponding filename
// and caches this information.
func (b *BaseReporter) ExecutableMetadata(args *ExecutableMetadataArgs) {
	b.pdata.Executables.Add(args.FileID, samples.ExecInfo{
		FileName:   args.FileName,
		GnuBuildID: args.GnuBuildID,
	})
}

func (*BaseReporter) ReportMetrics(_ uint32, _ []uint32, _ []int64) {}

func (*BaseReporter) SupportsReportTraceEvent() bool { return true }

// ReportTraceEvent enqueues reported trace events for the reporter.
func (b *BaseReporter) ReportTraceEvent(trace *libpf.Trace, meta *TraceEventMeta) {
	traceEventsMap := b.traceEvents.WLock()
	defer b.traceEvents.WUnlock(&traceEventsMap)

	var extraMeta any
	if b.cfg.ExtraSampleAttrProd != nil {
		extraMeta = b.cfg.ExtraSampleAttrProd.CollectExtraSampleMeta(trace, meta)
	}

	containerID, err := libpf.LookupCgroupv2(b.cgroupv2ID, meta.PID)
	if err != nil {
		log.Debugf("Failed to get a cgroupv2 ID as container ID for PID %d: %v",
			meta.PID, err)
	}

	key := samples.TraceAndMetaKey{
		Hash:           trace.Hash,
		Comm:           meta.Comm,
		Executable:     meta.Executable,
		ApmServiceName: meta.APMServiceName,
		ContainerID:    containerID,
		Pid:            int64(meta.PID),
		ExtraMeta:      extraMeta,
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

// FrameMetadata accepts metadata associated with a frame and caches this information.
func (b *BaseReporter) FrameMetadata(args *FrameMetadataArgs) {
	fileID := args.FrameID.FileID()
	addressOrLine := args.FrameID.AddressOrLine()

	log.Debugf("FrameMetadata [%x] %v+%v at %v:%v",
		fileID, args.FunctionName, args.FunctionOffset,
		args.SourceFile, args.SourceLine)

	if frameMapLock, exists := b.pdata.Frames.GetAndRefresh(fileID,
		pdata.FramesCacheLifetime); exists {
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
	b.pdata.Frames.Add(fileID, &mu)
}

// setResource sets the resource information of the origin of the profiles.
// Next step: maybe extend this information with go.opentelemetry.io/otel/sdk/resource.
func (b *BaseReporter) setResource(rp pprofile.ResourceProfiles) {
	keys := b.hostmetadata.Keys()
	attrs := rp.Resource().Attributes()

	// Add hostmedata to the attributes.
	for _, k := range keys {
		if v, ok := b.hostmetadata.Get(k); ok {
			attrs.PutStr(k, v)
		}
	}

	// Add event specific attributes.
	// These attributes are also included in the host metadata, but with different names/keys.
	// That makes our hostmetadata attributes incompatible with OTEL collectors.
	attrs.PutStr(string(semconv.HostIDKey), b.hostID)
	attrs.PutStr(string(semconv.HostIPKey), b.ipAddress)
	attrs.PutStr(string(semconv.HostNameKey), b.hostName)
	attrs.PutStr(string(semconv.ServiceVersionKey), b.version)
	attrs.PutStr("os.kernel", b.kernelVersion)
}
