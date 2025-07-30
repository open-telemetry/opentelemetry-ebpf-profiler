// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"context"
	"time"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/reporter/samples"
)

// Reporter is the top-level interface implemented by a full reporter.
type Reporter interface {
	TraceReporter
	SymbolReporter
	HostMetadataReporter

	// Start starts the reporter in the background.
	//
	// If the reporter needs to perform a long-running starting operation then it
	// is recommended that Start() returns quickly and the long-running operation
	// is performed in the background.
	Start(context.Context) error

	// Stop triggers a graceful shutdown of the reporter.
	Stop()
}

type TraceReporter interface {
	// ReportTraceEvent accepts a trace event (trace metadata with frames)
	// and enqueues it for reporting to the backend.
	// If handling the trace event fails it returns an error.
	ReportTraceEvent(trace *libpf.Trace, meta *samples.TraceEventMeta) error
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

type SymbolReporter interface {
	// ExecutableKnown may be used to query the reporter if the FileID is known.
	// The callers of ExecutableMetadata can optionally use this method to determine if the data
	// is already cached and avoid extra work resolving the metadata. If the reporter returns false,
	// the caller will resolve the executable metadata and submit it to the reporter
	// via a subsequent ExecutableMetadata call.
	ExecutableKnown(fileID libpf.FileID) bool

	// ExecutableMetadata accepts a FileID with the corresponding filename
	// and takes some action with it (for example, it might cache it for
	// periodic reporting to a backend).
	//
	// The `Open` argument can be used to open the executable for reading. Interpreters
	// that don't support this may pass a `nil` function pointer. Implementations that
	// wish to upload executables should NOT block this function to do so and instead just
	// open the file and then enqueue the upload in the background.
	ExecutableMetadata(args *ExecutableMetadataArgs)
}

type HostMetadataReporter interface {
	// ReportHostMetadata enqueues host metadata for sending (to the collection agent).
	ReportHostMetadata(metadataMap map[string]string)

	// ReportHostMetadataBlocking sends host metadata to the collection agent.
	ReportHostMetadataBlocking(ctx context.Context, metadataMap map[string]string,
		maxRetries int, waitRetry time.Duration) error
}
