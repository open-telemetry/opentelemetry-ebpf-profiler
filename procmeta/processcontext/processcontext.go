// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package processcontext implements the OpenTelemetry Process Context sharing
// protocol for reading resource attributes from an external process.
//
// See [OTEP 4719].
//
// [OTEP 4719]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/oteps/profiles/4719-process-ctx.md
package processcontext // import "go.opentelemetry.io/ebpf-profiler/procmeta/processcontext"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"structs"
	"unsafe"

	"go.opentelemetry.io/collector/pdata/pcommon"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	processcontextpb "go.opentelemetry.io/proto/otlp/processcontext/v1development"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
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
	ContextMappingMemfd        = "/memfd:OTEL_CTX"
	ContextMappingMemfdDeleted = "/memfd:OTEL_CTX (deleted)"
	ContextMappingMemfdNamed   = "[anon_shmem:OTEL_CTX]"
	ContextMappingAnonNamed    = "[anon:OTEL_CTX]"

	// default maximum number of read attempts on concurrent updates
	defaultMaxAttempts = 3

	// Signature
	signatureOTELCTX = "OTEL_CTX"

	// Expected format version
	supportedVersion = 2

	// Maximum payload size
	maxPayloadSize = 65536

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

// Info is a snapshot of process context. The pointed-to Resource and
// ExtraAttributes are shared by pointer across goroutines (process-manager
// writer, reporter) without locking; once an Info is published they
// MUST be treated as read-only by all holders.
type Info struct {
	Resource *pcommon.Resource
	// ExtraAttributes holds the attributes a process publishes outside its resource.
	// Decoded, but contributed nowhere yet: sample or resource scope is deliberately
	// still open, so the enricher returns Resource alone.
	ExtraAttributes *pcommon.Map
	PublishedAtNs   uint64
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
// Retries on concurrent updates, up to maxAttempts total attempts.
// If maxAttempts is 0, the default value is used.
func Read(addr libpf.Address, rm remotememory.RemoteMemory, lastPublishedAtNs uint64, maxAttempts int) (Info, error) {
	if maxAttempts == 0 {
		maxAttempts = defaultMaxAttempts
	}
	var lastErr error

	for range maxAttempts {
		processCtx, err := readOnce(addr, rm, lastPublishedAtNs)
		if err == nil {
			return processCtx, nil
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

// Resolve reads the process context a process publishes in its context region,
// returning (info, true) when the contribution changed and (_, false) to leave the
// published one untouched.
//
// mappingAddr=0 means the region was not observed this sync; with
// oldPublishedAtNs > 0 it disappeared, and the contribution is withdrawn.
//
// An exec needs no handling here: the caller drops oldPublishedAtNs with the
// contribution, so a region republished at a lower timestamp is read afresh.
func Resolve(
	mappingAddr uint64, pid libpf.PID, rm remotememory.RemoteMemory,
	oldPublishedAtNs uint64,
) (Info, bool) {
	if mappingAddr == 0 {
		// Withdraw a context whose region is gone; otherwise this process simply does
		// not publish one.
		return Info{}, oldPublishedAtNs != 0
	}

	// Workaround for a CodeQL warning about uint64 -> uintptr (libpf.Address) overflow.
	addr := libpf.Address(mappingAddr & uint64(^libpf.Address(0)))

	processCtx, err := Read(addr, rm, oldPublishedAtNs, 0)
	switch {
	case err == nil:
		// New process context read successfully, publish it.
		return processCtx, true
	case errors.Is(err, ErrNoUpdate), errors.Is(err, ErrConcurrentUpdate):
		// Payload unchanged, or a writer was mid-update: keep what was published
		// before, which is nothing at all on the round following an exec.
		return Info{}, false
	default:
		log.Debugf("Failed to read ProcessContext for PID %d: %v", pid, err)
	}

	// The payload could not be read: withdraw rather than keep a stale context.
	return Info{}, true
}

func IsContextMapping(isExecutable bool, mappingPath string) bool {
	return !isExecutable && (mappingPath == ContextMappingMemfd ||
		mappingPath == ContextMappingMemfdDeleted ||
		mappingPath == ContextMappingAnonNamed ||
		mappingPath == ContextMappingMemfdNamed)
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

	var resource *pcommon.Resource
	if ctx.Resource != nil {
		r := pcommon.NewResource()
		for _, attr := range ctx.Resource.Attributes {
			if v, ok := convertAnyValue(attr.Value); ok {
				v.MoveTo(r.Attributes().PutEmpty(attr.Key))
			}
		}
		resource = &r
	}

	var extraAttributes *pcommon.Map
	if ctx.Attributes != nil {
		m := pcommon.NewMap()
		for _, attr := range ctx.Attributes {
			if v, ok := convertAnyValue(attr.Value); ok {
				v.MoveTo(m.PutEmpty(attr.Key))
			}
		}
		extraAttributes = &m
	}
	return Info{Resource: resource, ExtraAttributes: extraAttributes, PublishedAtNs: hdr.MonotonicPublishedAtNs}, nil
}

// convertAnyValue converts a commonpb.AnyValue to a pcommon.Value, including nested
// maps and arrays. Returns (_, false) for nil inputs and unknown variants, so
// callers skip them rather than emit phantom empty entries.
func convertAnyValue(src *commonpb.AnyValue) (pcommon.Value, bool) {
	if src == nil {
		return pcommon.Value{}, false
	}
	switch v := src.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return pcommon.NewValueStr(v.StringValue), true
	case *commonpb.AnyValue_BoolValue:
		return pcommon.NewValueBool(v.BoolValue), true
	case *commonpb.AnyValue_IntValue:
		return pcommon.NewValueInt(v.IntValue), true
	case *commonpb.AnyValue_DoubleValue:
		return pcommon.NewValueDouble(v.DoubleValue), true
	case *commonpb.AnyValue_BytesValue:
		val := pcommon.NewValueBytes()
		val.Bytes().FromRaw(v.BytesValue)
		return val, true
	case *commonpb.AnyValue_ArrayValue:
		val := pcommon.NewValueSlice()
		if v.ArrayValue != nil {
			sl := val.Slice()
			sl.EnsureCapacity(len(v.ArrayValue.Values))
			for _, item := range v.ArrayValue.Values {
				if itemVal, ok := convertAnyValue(item); ok {
					itemVal.MoveTo(sl.AppendEmpty())
				}
			}
		}
		return val, true
	case *commonpb.AnyValue_KvlistValue:
		val := pcommon.NewValueMap()
		if v.KvlistValue != nil {
			m := val.Map()
			m.EnsureCapacity(len(v.KvlistValue.Values))
			for _, kv := range v.KvlistValue.Values {
				if kvVal, ok := convertAnyValue(kv.Value); ok {
					kvVal.MoveTo(m.PutEmpty(kv.Key))
				}
			}
		}
		return val, true
	default:
		log.Debugf("convertAnyValue: unknown AnyValue variant %T, skipping", v)
		return pcommon.Value{}, false
	}
}
