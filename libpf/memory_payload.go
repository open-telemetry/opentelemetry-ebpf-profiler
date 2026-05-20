// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

// MemoryPayloadKind identifies which counter pair a synthetic
// MemoryPayloadFrame holds. The kind is stored in Frame.FunctionOffset so
// payload frames can be decoded independently of their position in a trace.
type MemoryPayloadKind uint32

const (
	// MemoryPayloadAllocs marks a frame whose AddressOrLineno is the
	// allocation count and SourceLine is the total bytes allocated.
	MemoryPayloadAllocs MemoryPayloadKind = 0
	// MemoryPayloadFrees marks a frame whose AddressOrLineno is the free
	// count and SourceLine is the total bytes freed.
	MemoryPayloadFrees MemoryPayloadKind = 1
)

// NewMemoryPayloadFrame returns a synthetic frame carrying a memory-origin
// counter pair. Reporters consuming a memory-origin trace decode the alloc
// totals from one MemoryPayloadAllocs frame and the free totals from one
// MemoryPayloadFrees frame; either may be omitted if its counters are zero.
//
// Each frame uses three uint64-sized fields:
//
//	FunctionOffset  = MemoryPayloadKind   (allocs vs frees)
//	AddressOrLineno = count
//	SourceLine      = bytes
func NewMemoryPayloadFrame(kind MemoryPayloadKind, count, bytes uint64) Frame {
	return Frame{
		Type:            MemoryPayloadFrame,
		FunctionOffset:  uint32(kind),
		AddressOrLineno: AddressOrLineno(count),
		SourceLine:      SourceLineno(bytes),
	}
}

// DecodeMemoryPayload returns the (kind, count, bytes) triple stored on a
// synthetic memory-payload frame. The caller is responsible for ensuring
// f.Type == MemoryPayloadFrame before calling.
func DecodeMemoryPayload(f Frame) (kind MemoryPayloadKind, count, bytes uint64) {
	return MemoryPayloadKind(f.FunctionOffset),
		uint64(f.AddressOrLineno),
		uint64(f.SourceLine)
}
