// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processcontext // import "go.opentelemetry.io/ebpf-profiler/processcontext"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"structs"
	"sync/atomic"
	"unsafe"

	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	processcontextpb "go.opentelemetry.io/ebpf-profiler/processcontext/v1development"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const (
	// OTel process context is published in a mapping:
	// - based on a memfd file descriptor named "OTEL_CTX" when memfd_create is available.
	// - based on an anonymous private mapping when memfd_create is not available
	// In both cases, an attempt is made to name the mapping "OTEL_CTX" using prctl(PR_SET_VMA_ANON_NAME) which may fail depending on kernel version/configuration.
	// Consequently the mapping can show up with 3 different names:
	// - "/memfd:OTEL_CTX": memfd-based mapping and prctl failed
	// - "[anon_shmem:OTEL_CTX]": memfd-based mapping and prctl succeeded
	// - "[anon:OTEL_CTX]": anonymous mapping and prctl succeeded
	// Case where both memfd_create and prctl fail is considered a failure and is not supported.
	ContextMappingMemfd      = "/memfd:OTEL_CTX"
	ContextMappingMemfdNamed = "[anon_shmem:OTEL_CTX]"
	ContextMappingAnonNamed  = "[anon:OTEL_CTX]"

	// Signature
	signatureOTELCTX = "OTEL_CTX"

	// Expected format version
	supportedVersion = 2

	// Maximum payload size
	maxPayloadSize = 65536

	// Maximum retries for concurrent updates
	maxRetries = 3

	// Offset of the MonotonicPublishedAtNs field in the header struct
	monotonicPublishedAtNsOffset = libpf.Address(unsafe.Offsetof(header{}.MonotonicPublishedAtNs))
)

var (
	// ErrInvalidContext indicates the ProcessContext has invalid format, signature, version, or size.
	ErrInvalidContext = errors.New("invalid ProcessContext")

	// ErrConcurrentUpdate indicates the ProcessContext was updated during read.
	ErrConcurrentUpdate = errors.New("concurrent ProcessContext update detected")

	// ErrNoUpdate indicates the ProcessContext has not been updated since it was last published.
	ErrNoUpdate = errors.New("ProcessContext has not been updated")
)

type Info struct {
	Context       *processcontextpb.ProcessContext
	PublishedAtNs uint64
}

// header represents the 32-byte memory region header per OTEP #4719.
type header struct {
	_                      structs.HostLayout
	Signature              [8]byte // "OTEL_CTX"
	Version                uint32  // Format version (2)
	PayloadSize            uint32  // Size of protobuf payload in bytes
	MonotonicPublishedAtNs uint64  // Monotonic clock timestamp from `CLOCK_BOOTTIME` of when the context was published, in nanoseconds
	PayloadPtr             uint64  // Memory pointer to protobuf payload
}

// Read reads ProcessContext from remote process memory using the provided address.
// Returns ErrInvalidContext if the process has no ProcessContext memory region.
// Retries up to maxRetries times when concurrent updates are detected.
func Read(addr libpf.Address, rm remotememory.RemoteMemory, lastPublishedAtNs uint64) (Info, error) {
	var lastErr error

	// Find the ProcessContext mapping
	for range maxRetries {
		ctx, err := readOnce(addr, rm, lastPublishedAtNs)
		if err == nil {
			return ctx, nil
		}
		if !errors.Is(err, ErrConcurrentUpdate) {
			return Info{}, err
		}
		lastErr = err
	}
	return Info{}, lastErr
}

// readOnce performs a single attempt to read ProcessContext.
func readOnce(mappingAddr libpf.Address, rm remotememory.RemoteMemory, lastPublishedAtNs uint64) (Info, error) {
	monotonicPublishedAtNs, err := readTimestamp(rm, mappingAddr)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %w",
			ErrInvalidContext, err)
	}
	if monotonicPublishedAtNs == 0 {
		return Info{}, ErrConcurrentUpdate
	}

	// Check if the context was published after the last published timestamp
	if monotonicPublishedAtNs <= lastPublishedAtNs {
		return Info{}, ErrNoUpdate
	}

	// Memory barrier to ensure the timestamp is read before the header
	memoryBarrier()

	// Read and validate the header
	hdr, err := readHeader(rm, mappingAddr)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %w",
			ErrInvalidContext, err)
	}

	// Read the payload
	ctx, ctxErr := readPayload(rm, hdr)
	// Do not check for errors here as the context read might have failed due to
	// a concurrent update occurring between the header read and the payload read.
	// We will check for context read error after re-reading the header.

	// Memory barrier to ensure the header is read before the timestamp (again)
	memoryBarrier()

	// Re-read the timestamp to check for concurrent updates
	monotonicPublishedAtNs2, err := readTimestamp(rm, mappingAddr)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %w",
			ErrInvalidContext, err)
	}

	if monotonicPublishedAtNs != monotonicPublishedAtNs2 {
		return Info{}, ErrConcurrentUpdate
	}

	if ctxErr != nil {
		return Info{}, fmt.Errorf("%w: %w", ErrInvalidContext, ctxErr)
	}

	return ctx, nil
}

func IsContextMapping(mappingPath string) bool {
	// In some cases the name can show up in proc as "/memfd:OTEL_CTX (deleted)"
	// but the " (deleted)" suffix is separately trimmed by parseMappings
	return mappingPath == ContextMappingMemfd ||
		mappingPath == ContextMappingAnonNamed ||
		mappingPath == ContextMappingMemfdNamed
}

func readTimestamp(rm remotememory.RemoteMemory, headerAddr libpf.Address) (uint64, error) {
	var buf [8]byte
	if err := rm.Read(headerAddr+monotonicPublishedAtNsOffset, buf[:]); err != nil {
		return 0, fmt.Errorf("failed to read timestamp: %w", err)
	}
	return binary.LittleEndian.Uint64(buf[:]), nil
}

// readHeader reads and validates the 32-byte ProcessContext header.
func readHeader(rm remotememory.RemoteMemory, headerAddr libpf.Address) (header, error) {
	// Read the 32-byte header
	var hdr header
	if err := rm.Read(headerAddr, pfunsafe.FromPointer(&hdr)); err != nil {
		return header{}, fmt.Errorf("failed to read ProcessContext header: %w", err)
	}

	if pfunsafe.ToString(hdr.Signature[:]) != signatureOTELCTX {
		return header{}, fmt.Errorf("invalid signature: got %q, want %q",
			string(hdr.Signature[:]), signatureOTELCTX)
	}
	if hdr.Version != supportedVersion {
		return header{}, fmt.Errorf("invalid version: got %d, want %d",
			hdr.Version, supportedVersion)
	}

	// Validate payload size
	if hdr.PayloadSize == 0 || hdr.PayloadSize > maxPayloadSize {
		return header{}, fmt.Errorf("invalid payload size: %d bytes (max %d)",
			hdr.PayloadSize, maxPayloadSize)
	}

	return hdr, nil
}

func readPayload(rm remotememory.RemoteMemory, hdr header) (Info, error) {
	// Read the protobuf payload from remote memory
	payloadBytes := make([]byte, hdr.PayloadSize)
	err := rm.Read(libpf.Address(hdr.PayloadPtr), payloadBytes)
	if err != nil {
		return Info{}, fmt.Errorf("failed to read payload: %w", err)
	}

	// Deserialize the ProcessContext protobuf message
	ctx := &processcontextpb.ProcessContext{}
	if err := proto.Unmarshal(payloadBytes, ctx); err != nil {
		return Info{}, fmt.Errorf("failed to unmarshal ProcessContext: %w", err)
	}

	return Info{Context: ctx, PublishedAtNs: hdr.MonotonicPublishedAtNs}, nil
}

func memoryBarrier() {
	// On ARM64, atomic add will compile as LDADDAL which will act as a full memory barrier.
	var fence uint64
	atomic.AddUint64(&fence, 0)
}
