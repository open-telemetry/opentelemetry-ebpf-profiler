// This file contains definitions for the V8 tracer

// V8 constants for the tags. Hard coded to optimize code size and speed.
// They are unlikely to change, and likely require larger modifications on change.

// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#52
#define V8_SmiTag            0x0
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#54
#define V8_SmiTagMask        0x1
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#91
#define V8_SmiTagShift       1
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#98
#define V8_SmiValueShift     32
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#39
#define V8_HeapObjectTag     0x1
// https://chromium.googlesource.com/v8/v8.git/+/refs/heads/9.2.230/include/v8-internal.h#42
#define V8_HeapObjectTagMask 0x3UL

// The first V8 frame variable is split to object pointer (aligned to 8 bytes),
// and the zero bits due to alignment are reused as the following flags. For
// all types except MARKER the object pointer is the SharedFunctionInfo. The
// Code pointer is always sent as the second frame variable, and is valid for
// the NATIVE_CODE type.
#define V8_FRAME_TYPE_MARKER      0x0
#define V8_FRAME_TYPE_BYTECODE    0x1
#define V8_FRAME_TYPE_NATIVE_SFI  0x2
#define V8_FRAME_TYPE_NATIVE_CODE 0x3
#define V8_FRAME_TYPE_MASK        0x7

// The V8 frame header data holds the marker, or the bytecode or native PC
// delta, in its low 32 bits. NATIVE_CODE frames also carry the CodeKind above
// the delta, which the agent uses to validate its cached Code data.
#define V8_DATA_DELTA_MASK      0xffffffff
#define V8_DATA_CODE_KIND_SHIFT 32
#define V8_DATA_CODE_KIND_MASK  0xff

// Leaptiering (V8_ENABLE_LEAPTIERING) JSDispatchTable constants. Under leaptiering
// the JSFunction holds a 32-bit dispatch handle that indexes a JSDispatchTable;
// each 16-byte entry encodes the Code pointer in its second word.
// kJSDispatchHandleShift (src/common/globals.h), 8 unless V8_LOWER_LIMITS_MODE.
#define V8_JSDISPATCH_HANDLE_SHIFT         8
// sizeof(JSDispatchEntry) == kJSDispatchTableEntrySize (src/common/globals.h).
#define V8_JSDISPATCH_ENTRY_SIZE           16
// JSDispatchEntry::encoded_word_ offset (== kCodeObjectOffset == kSystemPointerSize).
#define V8_JSDISPATCH_ENCODED_WORD_OFFSET  8
// JSDispatchEntry::kObjectPointerShift: Code pointer occupies the high bits.
#define V8_JSDISPATCH_OBJECT_POINTER_SHIFT 16
