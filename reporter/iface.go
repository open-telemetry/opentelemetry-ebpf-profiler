// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
)

// Reporter is the top-level interface implemented by a full reporter.
type Reporter interface {
	TraceReporter
	SymbolReporter
	HostMetadataReporter
	MetricsReporter

	// Stop triggers a graceful shutdown of the reporter.
	Stop()
	// GetMetrics returns the reporter internal metrics.
	GetMetrics() Metrics
}

type TraceEventMeta struct {
	Timestamp      libpf.UnixTime64
	Comm           string
	APMServiceName string
	PID, TID       libpf.PID
}

type TraceReporter interface {
	// ReportFramesForTrace accepts a trace with the corresponding frames
	// and caches this information before a periodic reporting to the backend.
	ReportFramesForTrace(trace *libpf.Trace)

	// ReportCountForTrace accepts a hash of a trace with a corresponding count and
	// caches this information before a periodic reporting to the backend.
	ReportCountForTrace(traceHash libpf.TraceHash, count uint16, meta *TraceEventMeta)

	// ReportTraceEvent accepts a trace event (trace metadata with frames and counts)
	// and caches it for reporting to the backend. It returns true if the event was
	// enqueued for reporting, and false if the event was ignored.
	ReportTraceEvent(trace *libpf.Trace, meta *TraceEventMeta)

	// SupportsReportTraceEvent returns true if the reporter supports reporting trace events
	// via ReportTraceEvent().
	SupportsReportTraceEvent() bool
}

// ExecutableOpener is a function that attempts to open an executable.
type ExecutableOpener = func() (process.ReadAtCloser, error)

// ExecutableMetadataArgs collects metadata about a discovered
// executable, for reporting to a SymbolReporter via the ExecutableMetadata function.
type ExecutableMetadataArgs struct {
	// FileID is a unique identifier of the executable.
	FileID libpf.FileID
	// FileName is the base filename of the executable.
	FileName string
	// GnuBuildID is the GNU build ID from .note.gnu.build-id, if any.
	GnuBuildID string
	// DebuglinkFileName is the path to the matching debug file
	// from the .gnu.debuglink, if any. The caller should
	// verify that the file in question matches the GnuBuildID of this executable..
	DebuglinkFileName string
	// Interp is the discovered interpreter type of this executable, if any.
	Interp libpf.InterpreterType
	// Open is a function that can be used to open the executable for reading,
	// or nil for interpreters that don't support this.
	Open ExecutableOpener
}

// FrameMetadataArgs collects metadata about a single frame in a trace, for
// reporting it to a SymbolReporter via the FrameMetadata method.
type FrameMetadataArgs struct {
	// FrameID is a unique identifier for the frame.
	FrameID libpf.FrameID
	// FunctionName is the name of the function for the frame.
	FunctionName string
	// SourceFile is the source code file name for the frame.
	SourceFile string
	// SourceLine is the source code level line number of this frame.
	SourceLine libpf.SourceLineno
	// FunctionOffset is the line offset from function start line for the frame.
	FunctionOffset uint32
}

type SymbolReporter interface {
	// ExecutableMetadata accepts a FileID with the corresponding filename
	// and takes some action with it (for example, it might cache it for
	// periodic reporting to a backend).
	//
	// The `Open` argument can be used to open the executable for reading. Interpreters
	// that don't support this may pass a `nil` function pointer. Implementations that
	// wish to upload executables should NOT block this function to do so and instead just
	// open the file and then enqueue the upload in the background.
	ExecutableMetadata(args *ExecutableMetadataArgs)

	// FrameKnown may be used to query the reporter if the FrameID is known. The interpreter
	// modules can optionally use this method to determine if the data is already cached
	// and avoid extra work resolving the metadata. If the reporter returns false,
	// the intepreter plugin will resolve the frame metadata and submit it to the reporter
	// via a subsequent FrameMetdata call.
	FrameKnown(frameID libpf.FrameID) bool

	// FrameMetadata accepts metadata associated with a frame and caches this information before
	// a periodic reporting to the backend.
	FrameMetadata(frameMetadata *FrameMetadataArgs)
}

type HostMetadataReporter interface {
	// ReportHostMetadata enqueues host metadata for sending (to the collection agent).
	ReportHostMetadata(metadataMap map[string]string)

	// ReportHostMetadataBlocking sends host metadata to the collection agent.
	ReportHostMetadataBlocking(ctx context.Context, metadataMap map[string]string,
		maxRetries int, waitRetry time.Duration) error
}

type MetricsReporter interface {
	// ReportMetrics accepts an id with a corresponding value and caches this
	// information before a periodic reporting to the backend.
	ReportMetrics(timestamp uint32, ids []uint32, values []int64)
}
