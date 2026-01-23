// Provides the frame type markers so they can be included by both
// the Go and eBPF components.
//
// NOTE: As this is included by both kernel and user-land components, do not
// include any files that cannot be included in both contexts.

#ifndef OPTI_FRAMETYPES_H
#define OPTI_FRAMETYPES_H

// Indicates that the interpreter/runtime this frame belongs to is unknown.
#define FRAME_MARKER_UNKNOWN 0x0
// Indicates a Python frame
#define FRAME_MARKER_PYTHON  0x1
// Indicates a PHP frame
#define FRAME_MARKER_PHP     0x2
// Indicates a native frame
#define FRAME_MARKER_NATIVE  0x3
// Indicates a kernel frame
#define FRAME_MARKER_KERNEL  0x4
// Indicates a HotSpot frame
#define FRAME_MARKER_HOTSPOT 0x5
// Indicates a Ruby frame
#define FRAME_MARKER_RUBY    0x6
// Indicates a Perl frame
#define FRAME_MARKER_PERL    0x7
// Indicates a V8 frame
#define FRAME_MARKER_V8      0x8
// Indicates a PHP JIT frame
#define FRAME_MARKER_PHP_JIT 0x9
// Indicates a Dotnet frame
#define FRAME_MARKER_DOTNET  0xA
// Indicates a Go frame
#define FRAME_MARKER_GO      0xB
// Indicates a BEAM frame
#define FRAME_MARKER_BEAM    0xC

// Frame flags
// Indicates that this frame is an error frame.
#define FRAME_FLAG_ERROR          (1U << 0)
// Indicates that this frame PC is a return address.
#define FRAME_FLAG_RETURN_ADDRESS (1U << 1)
// Indicates that the frame contains process specific addresses,
// and the PID should be included in the caching key.
#define FRAME_FLAG_PID_SPECIFIC   (1U << 2)

// HotSpot frame subtypes stored in a bitfield of the trace->lines[]
#define FRAME_HOTSPOT_STUB        0
#define FRAME_HOTSPOT_VTABLE      1
#define FRAME_HOTSPOT_INTERPRETER 2
#define FRAME_HOTSPOT_NATIVE      3

#define RUBY_FRAME_TYPE_NONE      0
#define RUBY_FRAME_TYPE_CME_ISEQ  1
#define RUBY_FRAME_TYPE_CME_CFUNC 2
#define RUBY_FRAME_TYPE_ISEQ      3
#define RUBY_FRAME_TYPE_JIT       5

#endif
