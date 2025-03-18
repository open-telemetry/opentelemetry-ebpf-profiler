//go:build ignore

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support // import "go.opentelemetry.io/ebpf-profiler/support"

/*
#include "./ebpf/types.h"
#include "./ebpf/frametypes.h"
*/
import "C"

const (
	FrameMarkerUnknown  = C.FRAME_MARKER_UNKNOWN
	FrameMarkerErrorBit = C.FRAME_MARKER_ERROR_BIT
	FrameMarkerPython   = C.FRAME_MARKER_PYTHON
	FrameMarkerNative   = C.FRAME_MARKER_NATIVE
	FrameMarkerPHP      = C.FRAME_MARKER_PHP
	FrameMarkerPHPJIT   = C.FRAME_MARKER_PHP_JIT
	FrameMarkerKernel   = C.FRAME_MARKER_KERNEL
	FrameMarkerHotSpot  = C.FRAME_MARKER_HOTSPOT
	FrameMarkerRuby     = C.FRAME_MARKER_RUBY
	FrameMarkerPerl     = C.FRAME_MARKER_PERL
	FrameMarkerV8       = C.FRAME_MARKER_V8
	FrameMarkerDotnet   = C.FRAME_MARKER_DOTNET
	FrameMarkerAbort    = C.FRAME_MARKER_ABORT
)

const (
	ProgUnwindStop    = C.PROG_UNWIND_STOP
	ProgUnwindNative  = C.PROG_UNWIND_NATIVE
	ProgUnwindHotspot = C.PROG_UNWIND_HOTSPOT
	ProgUnwindPython  = C.PROG_UNWIND_PYTHON
	ProgUnwindPHP     = C.PROG_UNWIND_PHP
	ProgUnwindRuby    = C.PROG_UNWIND_RUBY
	ProgUnwindPerl    = C.PROG_UNWIND_PERL
	ProgUnwindV8      = C.PROG_UNWIND_V8
	ProgUnwindDotnet  = C.PROG_UNWIND_DOTNET
	ProgGoLabels      = C.PROG_GO_LABELS
)

const (
	DeltaCommandFlag = C.STACK_DELTA_COMMAND_FLAG

	MergeOpcodeNegative = C.MERGEOPCODE_NEGATIVE
)

const (
	EventTypeGenericPID = C.EVENT_TYPE_GENERIC_PID
)

const MaxFrameUnwinds = C.MAX_FRAME_UNWINDS

const (
	MetricIDBeginCumulative = C.metricID_BeginCumulative
)

const (
	BitWidthPID  = C.BIT_WIDTH_PID
	BitWidthPage = C.BIT_WIDTH_PAGE
)

const (
	// StackDeltaBucket[Smallest|Largest] define the boundaries of the bucket sizes of the various
	// nested stack delta maps.
	StackDeltaBucketSmallest = C.STACK_DELTA_BUCKET_SMALLEST
	StackDeltaBucketLargest  = C.STACK_DELTA_BUCKET_LARGEST

	// StackDeltaPage[Bits|Mask] determine the paging size of stack delta map information
	StackDeltaPageBits = C.STACK_DELTA_PAGE_BITS
	StackDeltaPageMask = C.STACK_DELTA_PAGE_MASK
)

const (
	HSTSIDIsStubBit       = C.HS_TSID_IS_STUB_BIT
	HSTSIDHasFrameBit     = C.HS_TSID_HAS_FRAME_BIT
	HSTSIDStackDeltaBit   = C.HS_TSID_STACK_DELTA_BIT
	HSTSIDStackDeltaMask  = C.HS_TSID_STACK_DELTA_MASK
	HSTSIDStackDeltaScale = C.HS_TSID_STACK_DELTA_SCALE
	HSTSIDSegMapBit       = C.HS_TSID_SEG_MAP_BIT
	HSTSIDSegMapMask      = C.HS_TSID_SEG_MAP_MASK
)

const (
	// PerfMaxStackDepth is the bpf map data array length for BPF_MAP_TYPE_STACK_TRACE traces
	PerfMaxStackDepth = C.PERF_MAX_STACK_DEPTH
)

const (
	TraceOriginUnknown  = C.TRACE_UNKNOWN
	TraceOriginSampling = C.TRACE_SAMPLING
	TraceOriginOffCPU   = C.TRACE_OFF_CPU
)

const OffCPUThresholdMax = C.OFF_CPU_THRESHOLD_MAX

type ApmIntProcInfo C.ApmIntProcInfo
type DotnetProcInfo C.DotnetProcInfo
type PHPProcInfo C.PHPProcInfo
type RubyProcInfo C.RubyProcInfo

const (
	sizeof_ApmIntProcInfo = C.sizeof_ApmIntProcInfo
	sizeof_DotnetProcInfo = C.sizeof_DotnetProcInfo
	sizeof_PHPProcInfo    = C.sizeof_PHPProcInfo
	sizeof_RubyProcInfo   = C.sizeof_RubyProcInfo
)
