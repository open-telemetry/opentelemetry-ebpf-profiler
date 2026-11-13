// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// Trace record handling errors: they indicate an eBPF/user space layout
// mismatch, which is fatal.
var (
	// ErrRecordTooSmall indicates a record shorter than the trace header.
	ErrRecordTooSmall = errors.New("trace record too small")
	// ErrRecordUnexpectedSize indicates a record whose sections exceed or
	// overlap the record.
	ErrRecordUnexpectedSize = errors.New("unexpected record size")
)

// traceRecordMaxSize is the maximum trace record size, plus slack for
// kernel padding.
const traceRecordMaxSize = support.Sizeof_TraceWithData + 8

// traceEvent is the pooled decoded form of a raw trace record; the decoded
// sections alias raw and are valid for its lifetime.
type traceEvent struct {
	// raw holds the copied record, as uint64 words for in-place section
	// decoding.
	raw [traceRecordMaxSize / 8]uint64
	// recordLen is the size of the copied record in bytes.
	recordLen int

	// CustomLabels holds the merged thread-context and Go custom labels.
	CustomLabels map[libpf.String]libpf.String
	Comm         libpf.Comm
	// ContextValues are the origin-specific values; the first, if any, is the
	// primary profile value.
	ContextValues []uint64
	KernelFrames  []uint64
	FrameData     []uint64

	// KTime is the capture time in CLOCK_BOOTTIME nanoseconds, see times.KTime.
	KTime     int64
	CpuID     uint32
	TID       libpf.PID
	PID       libpf.PID
	NumFrames uint16
	Origin    uint16
	TraceID   libpf.TraceID
	SpanID    libpf.SpanID
}

func (e *traceEvent) rawBytes() []byte {
	return unsafe.Slice((*byte)(unsafe.Pointer(&e.raw[0])), int(unsafe.Sizeof(e.raw)))
}

// validateRecord checks a record's header and section layout, so malformed
// records are rejected before decoding.
func validateRecord(raw []byte) error {
	if len(raw) < support.Sizeof_TraceHeader {
		return fmt.Errorf("%d < %d: %w", len(raw), support.Sizeof_TraceHeader, ErrRecordTooSmall)
	}
	ptr := (*support.Trace)(unsafe.Pointer(unsafe.SliceData(raw)))

	// NOTE: can't do exact check here: kernel adds a few padding bytes to messages.
	if len(raw) < support.Sizeof_TraceHeader+int(ptr.Variable_data_end) {
		return fmt.Errorf("%d < %d: %w", len(raw),
			support.Sizeof_TraceHeader+int(ptr.Variable_data_end), ErrRecordUnexpectedSize)
	}
	if int(ptr.Variable_data_end) > support.Sizeof_TraceWithData-support.Sizeof_TraceHeader {
		return fmt.Errorf("variable data end %d exceeds maximum %d: %w", ptr.Variable_data_end,
			support.Sizeof_TraceWithData-support.Sizeof_TraceHeader, ErrRecordUnexpectedSize)
	}

	// Sections are appended in a fixed order; a zero end means absent. The
	// first three hold uint64 values and must end 8-byte aligned.
	pos := uint16(0)
	for _, section := range [...]struct {
		end     uint16
		name    string
		aligned bool // section holds uint64 values
	}{
		{ptr.Context_value_end, "context value", true},
		{ptr.Kernel_frame_end, "kernel_frame", true},
		{ptr.Frame_data_end, "frame", true},
		{ptr.Golang_label_end, "golang label", false},
		{ptr.Thread_label_end, "thread label", false},
	} {
		if section.end == 0 {
			continue
		}
		if section.end < pos || section.end > ptr.Variable_data_end ||
			(section.aligned && section.end%8 != 0) {
			return fmt.Errorf("%s end %d: not in range [%d, %d]: %w",
				section.name, section.end, pos, ptr.Variable_data_end, ErrRecordUnexpectedSize)
		}
		pos = (section.end + 7) &^ 7
	}
	return nil
}

func newTraceEventPool() sync.Pool {
	return sync.Pool{
		New: func() any {
			return &traceEvent{}
		},
	}
}
