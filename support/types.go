// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// support maps the definitions from headers in the C world into a nice go way
package support // import "go.opentelemetry.io/ebpf-profiler/support"

/*
#include "./ebpf/types.h"
#include "./ebpf/frametypes.h"
*/
import "C"
import "fmt"

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
	FrameMarkerLuaJIT   = C.FRAME_MARKER_LUAJIT
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
	ProgUnwindLuaJIT  = C.PROG_UNWIND_LUAJIT
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

// EncodeBiasAndUnwindProgram encodes a bias_and_unwind_program value (for C.PIDPageMappingInfo)
// from a bias and unwind program values.
// This currently assumes a non-negative bias: this encoding may have to be changed if bias can be
// negative.
func EncodeBiasAndUnwindProgram(bias uint64,
	unwindProgram uint8) (uint64, error) {
	if (bias >> 56) > 0 {
		return 0, fmt.Errorf("unsupported bias value (too large): 0x%x", bias)
	}
	return bias | (uint64(unwindProgram) << 56), nil
}

// DecodeBiasAndUnwindProgram decodes the contents of the `bias_and_unwind_program` field in
// C.PIDPageMappingInfo and returns the corresponding bias and unwind program.
func DecodeBiasAndUnwindProgram(biasAndUnwindProgram uint64) (bias uint64, unwindProgram uint8) {
	bias = biasAndUnwindProgram & 0x00FFFFFFFFFFFFFF
	unwindProgram = uint8(biasAndUnwindProgram >> 56)
	return bias, unwindProgram
}

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
