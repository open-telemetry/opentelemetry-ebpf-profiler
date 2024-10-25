// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"time"

	lru "github.com/elastic/go-freelru"
	"go.opentelemetry.io/collector/consumer/consumerprofiles"
	"go.opentelemetry.io/collector/pdata/pprofile"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/xsync"
)

// Assert that we implement the full Reporter interface.
var _ Reporter = (*CollectorReporter)(nil)

// OTLPReporter receives and transforms information to be Collector Collector compliant.
type CollectorReporter struct {
	nextConsumer consumerprofiles.Profiles

	// hostmetadata stores metadata that is sent out with every request.
	hostmetadata *lru.SyncedLRU[string, string]

	// executables stores metadata for executables.
	executables *lru.SyncedLRU[libpf.FileID, execInfo]

	// frames maps frame information to its source location.
	frames *lru.SyncedLRU[libpf.FileID, *xsync.RWMutex[map[libpf.AddressOrLineno]sourceInfo]]
}

// NewCollector builds a new CollectorReporter
func NewCollector(nextConsumer consumerprofiles.Profiles) *CollectorReporter {
	return &CollectorReporter{
		nextConsumer: nextConsumer,
	}
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

// Stop is a NOP for CollectorReporter
func (r *CollectorReporter) Stop() {
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
func (r *CollectorReporter) ReportTraceEvent(_ *libpf.Trace, _ *TraceEventMeta) {
	// TODO: get a context provided by the trace handler ?
	ctx := context.Background()
	// TODO: build pdata
	data := pprofile.Profiles{}

	if r.nextConsumer != nil {
		// TODO: handle errors in trace handler ?
		_ = r.nextConsumer.ConsumeProfiles(ctx, data)
	}
}
