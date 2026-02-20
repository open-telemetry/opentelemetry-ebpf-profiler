// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process // import "go.opentelemetry.io/ebpf-profiler/process"

import (
	"errors"
	"fmt"
	"structs"

	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	processcontext "go.opentelemetry.io/ebpf-profiler/proto/processcontext"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

const (
	// Signature
	signatureOTELCTX = "OTEL_CTX"

	// Expected format version
	supportedVersion = 2

	// Maximum payload size
	maxPayloadSize = 16384

	// Maximum retries for concurrent updates
	maxRetries = 3

	MemfdContextMappingName      = "/memfd:OTEL_CTX"
	AnonymousContextMappingName  = "[anon:OTEL_CTX]"
	AnonSharedContextMappingName = "[anon_shmem:OTEL_CTX]"
)

var (
	// ErrInvalidContext indicates the ProcessContext has invalid format, signature, version, or size.
	ErrInvalidContext = errors.New("invalid ProcessContext")

	// ErrConcurrentUpdate indicates the ProcessContext was updated during read.
	ErrConcurrentUpdate = errors.New("concurrent ProcessContext update detected")

	// ErrNoUpdate indicates the ProcessContext has not been updated since the last published.
	ErrNoUpdate = errors.New("ProcessContext has not been updated since the last published")
)

type ProcessContextInfo struct {
	Context       *processcontext.ProcessContext
	PublishedAtNs uint64
}

// processContextHeader represents the 32-byte memory region header per OTEP #4719.
type processContextHeader struct {
	_             structs.HostLayout
	Signature     [8]byte // "OTEL_CTX"
	Version       uint32  // Format version (2)
	PayloadSize   uint32  // Size of protobuf payload in bytes
	PublishedAtNs uint64  // Nanoseconds since epoch timestamp
	PayloadPtr    uint64  // Memory pointer to protobuf payload
}

// ReadProcessContext reads ProcessContext from process memory using the provided mappings.
// Returns ErrProcessContextNotFound if the process has no ProcessContext memory region.
// Retries up to maxRetries times when concurrent updates are detected.
func ReadProcessContext(mapping *Mapping, rm remotememory.RemoteMemory, lastPublishedAtNs uint64) (ProcessContextInfo, error) {
	var lastErr error

	// Find the ProcessContext mapping
	for range maxRetries {
		ctx, err := readProcessContextOnce(mapping, rm, lastPublishedAtNs)
		if err == nil {
			return ctx, nil
		}
		if !errors.Is(err, ErrConcurrentUpdate) {
			return ProcessContextInfo{}, err
		}
		lastErr = err
	}
	return ProcessContextInfo{}, lastErr
}

// readProcessContextOnce performs a single attempt to read ProcessContext.
func readProcessContextOnce(mapping *Mapping, rm remotememory.RemoteMemory, lastPublishedAtNs uint64) (ProcessContextInfo, error) {
	// Read and validate the header
	hdr, err := readProcessContextHeader(rm, mapping)
	if err != nil {
		return ProcessContextInfo{}, fmt.Errorf("%w: %w",
			ErrInvalidContext, err)
	}

	if hdr.PublishedAtNs == 0 {
		return ProcessContextInfo{}, ErrConcurrentUpdate
	}

	// timestamp monotonicity is not guaranteed, so we only check if the timestamp has changed
	if hdr.PublishedAtNs == lastPublishedAtNs {
		return ProcessContextInfo{}, ErrNoUpdate
	}

	// Read the payload
	ctx, ctxErr := readProcessContext(rm, hdr)
	// Do not check for errors here as the context read might have failed due to
	// a concurrent update occurring between the header read and the payload read.
	// We will check for context read error after re-reading the header.

	// Re-read the header to check for concurrent updates
	hdr2, err := readProcessContextHeader(rm, mapping)
	if err != nil {
		return ProcessContextInfo{}, err
	}
	if hdr2.PublishedAtNs != hdr.PublishedAtNs {
		return ProcessContextInfo{}, ErrConcurrentUpdate
	}

	if ctxErr != nil {
		return ProcessContextInfo{}, fmt.Errorf("%w: %w", ErrInvalidContext, ctxErr)
	}

	return ctx, nil
}

func IsProcessContextMapping(mapping *Mapping) bool {
	path := mapping.Path.String()
	// In some cases the name can show up in proc as "/memfd:OTEL_CTX (deleted)"
	// but the " (deleted)" suffix is separately trimmed by parseMappings
	return path == MemfdContextMappingName ||
		path == AnonymousContextMappingName ||
		path == AnonSharedContextMappingName
}

// findContextMapping searches for the ProcessContext memory mapping.
func findContextMapping(mappings []Mapping) *Mapping {
	for i := range mappings {
		m := &mappings[i]
		if IsProcessContextMapping(m) {
			return m
		}
	}
	return nil
}

// readProcessContextHeader reads and validates the 32-byte ProcessContext header.
func readProcessContextHeader(rm remotememory.RemoteMemory, mapping *Mapping) (processContextHeader, error) {
	// Read the 32-byte header
	var hdr processContextHeader
	err := rm.Read(libpf.Address(mapping.Vaddr), pfunsafe.FromPointer(&hdr))
	if err != nil {
		return processContextHeader{}, fmt.Errorf("failed to read ProcessContext header: %w", err)
	}

	if pfunsafe.ToString(hdr.Signature[:]) != signatureOTELCTX {
		return processContextHeader{}, fmt.Errorf("invalid signature: got %q, want %q",
			string(hdr.Signature[:]), signatureOTELCTX)
	}
	if hdr.Version != supportedVersion {
		return processContextHeader{}, fmt.Errorf("invalid version: got %d, want %d",
			hdr.Version, supportedVersion)
	}

	// Validate payload size
	if hdr.PayloadSize == 0 || hdr.PayloadSize > maxPayloadSize {
		return processContextHeader{}, fmt.Errorf("invalid payload size: %d bytes (max %d)",
			hdr.PayloadSize, maxPayloadSize)
	}

	return hdr, nil
}

// readProcessContext reads the ProcessContext payload with retry logic for concurrent updates.
func readProcessContext(rm remotememory.RemoteMemory, hdr processContextHeader) (ProcessContextInfo, error) {
	// Read the protobuf payload from remote memory
	payloadBytes := make([]byte, hdr.PayloadSize)
	err := rm.Read(libpf.Address(hdr.PayloadPtr), payloadBytes)
	if err != nil {
		return ProcessContextInfo{}, fmt.Errorf("failed to read payload: %w", err)
	}

	// Deserialize the ProcessContext protobuf message
	ctx := &processcontext.ProcessContext{}
	if err := proto.Unmarshal(payloadBytes, ctx); err != nil {
		return ProcessContextInfo{}, fmt.Errorf("failed to unmarshal ProcessContext: %w", err)
	}

	return ProcessContextInfo{Context: ctx, PublishedAtNs: hdr.PublishedAtNs}, nil
}
