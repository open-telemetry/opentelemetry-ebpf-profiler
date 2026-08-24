// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package processcontext implements the OpenTelemetry Process Context sharing
// protocol for reading resource attributes from an external process.
//
// See [OTEP 4719].
//
// [OTEP 4719]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/oteps/profiles/4719-process-ctx.md
package processcontext // import "go.opentelemetry.io/ebpf-profiler/process/processcontext"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"structs"
	"unsafe"

	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.37.0"
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
	contextMappingMemfd        = "/memfd:OTEL_CTX"
	contextMappingMemfdDeleted = "/memfd:OTEL_CTX (deleted)"
	contextMappingMemfdNamed   = "[anon_shmem:OTEL_CTX]"
	contextMappingAnonNamed    = "[anon:OTEL_CTX]"

	defaultMaxAttempts = 3

	signatureOTELCTX = "OTEL_CTX"
	supportedVersion = 2
	maxPayloadSize   = 65536 // bytes

	monotonicPublishedAtNsOffset = libpf.Address(unsafe.Offsetof(header{}.MonotonicPublishedAtNs))

	// Env vars used to derive resource attributes.
	resourceAttrKey = "OTEL_RESOURCE_ATTRIBUTES"
	svcNameKey      = "OTEL_SERVICE_NAME"
)

var (
	// errInvalidContext indicates the ProcessContext has invalid format, signature, version, or size.
	errInvalidContext = errors.New("invalid ProcessContext")

	// errConcurrentUpdate indicates the ProcessContext was updated during read.
	errConcurrentUpdate = errors.New("concurrent ProcessContext update detected")

	// errNoUpdate indicates the ProcessContext has not been updated since it was last published.
	errNoUpdate = errors.New("ProcessContext has not been updated")
)

// Info is a snapshot of process context. attribute.Set is immutable, so the
// sets are safe to copy and share across goroutines without locking.
type Info struct {
	ResourceAttrs attribute.Set
	// Populated but unused until thread context lands.
	attributes    attribute.Set
	publishedAtNs uint64
}

// header represents the 32-byte memory region header per OTEP #4719.
type header struct {
	_                      structs.HostLayout
	Signature              [8]byte // "OTEL_CTX"
	Version                uint32
	PayloadSize            uint32 // bytes
	MonotonicPublishedAtNs uint64 // CLOCK_BOOTTIME
	PayloadPtr             uint64
}

// read reads ProcessContext from remote process memory at addr.
// Returns errInvalidContext if the process has no ProcessContext memory region.
// Retries concurrent updates up to maxAttempts times, or defaultMaxAttempts if 0.
func read(addr libpf.Address, rm remotememory.RemoteMemory, lastPublishedAtNs uint64, maxAttempts int) (Info, error) {
	if maxAttempts == 0 {
		maxAttempts = defaultMaxAttempts
	}
	var lastErr error

	for range maxAttempts {
		processCtx, err := readOnce(addr, rm, lastPublishedAtNs)
		if err == nil {
			return processCtx, nil
		}
		if !errors.Is(err, errConcurrentUpdate) {
			return Info{}, err
		}
		lastErr = err
	}
	return Info{}, lastErr
}

func readOnce(mappingAddr libpf.Address, rm remotememory.RemoteMemory, lastPublishedAtNs uint64) (Info, error) {
	monotonicPublishedAtNs, err := readTimestamp(rm, mappingAddr)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %w",
			errInvalidContext, err)
	}
	if monotonicPublishedAtNs == 0 {
		return Info{}, errConcurrentUpdate
	}

	if monotonicPublishedAtNs <= lastPublishedAtNs {
		return Info{}, errNoUpdate
	}

	hdr, err := readHeader(rm, mappingAddr)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %w",
			errInvalidContext, err)
	}

	ctx, ctxErr := readPayload(rm, hdr)
	// Deferred: the read may have failed only because of a concurrent update
	// between the header and the payload, which the timestamp recheck detects.

	monotonicPublishedAtNs2, err := readTimestamp(rm, mappingAddr)
	if err != nil {
		return Info{}, fmt.Errorf("%w: %w",
			errInvalidContext, err)
	}

	if monotonicPublishedAtNs != monotonicPublishedAtNs2 {
		return Info{}, errConcurrentUpdate
	}

	if ctxErr != nil {
		return Info{}, fmt.Errorf("%w: %w", errInvalidContext, ctxErr)
	}

	return ctx, nil
}

// Resolve reads the process context from a context mapping (if any) and merges
// attributes derived from OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES.
// Returns (_, false) to leave the previously-published context untouched.
//
// mappingAddr=0 means the mapping was not observed this sync. If old also
// carries a published context, the mapping disappeared.
// newProcessOrExec=true discards old and forces a rebuild so new env vars
// take effect even when the mapping is present.
func Resolve(
	mappingAddr uint64, pid libpf.PID, rm remotememory.RemoteMemory,
	old Info,
	envVars map[libpf.String]libpf.String,
	newProcessOrExec bool,
) (Info, bool) {
	if mappingAddr == 0 {
		if newProcessOrExec || old.publishedAtNs != 0 {
			return withMergedEnvVars(Info{}, envVars), true
		}
		return Info{}, false
	}

	// A new process or an exec rebuilds from scratch, so accept any timestamp.
	var lastPublishedAtNs uint64
	if !newProcessOrExec {
		lastPublishedAtNs = old.publishedAtNs
	}

	// Workaround for a CodeQL warning about uint64 -> uintptr (libpf.Address) overflow.
	addr := libpf.Address(mappingAddr & uint64(^libpf.Address(0)))

	processCtx, err := read(addr, rm, lastPublishedAtNs, 0)
	switch {
	case err == nil:
		return withMergedEnvVars(processCtx, envVars), true
	case errors.Is(err, errNoUpdate):
		return Info{}, false
	case errors.Is(err, errConcurrentUpdate):
		// Retries are exhausted, so prefer the previous context over dropping it.
		if !newProcessOrExec {
			return Info{}, false
		}
	default:
		log.Debugf("Failed to read ProcessContext for PID %d: %v", pid, err)
	}

	return withMergedEnvVars(Info{}, envVars), true
}

func IsContextMapping(isExecutable bool, mappingPath string) bool {
	return !isExecutable && (mappingPath == contextMappingMemfd ||
		mappingPath == contextMappingMemfdDeleted ||
		mappingPath == contextMappingAnonNamed ||
		mappingPath == contextMappingMemfdNamed)
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

	if hdr.PayloadSize == 0 || hdr.PayloadSize > maxPayloadSize {
		return header{}, fmt.Errorf("invalid payload size: %d bytes (max %d)",
			hdr.PayloadSize, maxPayloadSize)
	}

	return hdr, nil
}

func readPayload(rm remotememory.RemoteMemory, hdr header) (Info, error) {
	payloadBytes := make([]byte, hdr.PayloadSize)
	err := rm.Read(libpf.Address(hdr.PayloadPtr), payloadBytes)
	if err != nil {
		return Info{}, fmt.Errorf("failed to read payload: %w", err)
	}

	ctx := &processcontextpb.ProcessContext{}
	if err := proto.Unmarshal(payloadBytes, ctx); err != nil {
		return Info{}, fmt.Errorf("failed to unmarshal ProcessContext: %w", err)
	}

	return Info{
		ResourceAttrs: newAttributeSet(convertKeyValues(ctx.GetResource().GetAttributes())),
		attributes:    newAttributeSet(convertKeyValues(ctx.GetAttributes())),
		publishedAtNs: hdr.MonotonicPublishedAtNs,
	}, nil
}

// newAttributeSet builds a Set from attrs, dropping entries with an empty key
// per the OTel spec. Keys inside a MAP value are not attribute keys and stay.
func newAttributeSet(attrs []attribute.KeyValue) attribute.Set {
	s, _ := attribute.NewSetWithFiltered(attrs, attribute.KeyValue.Valid)
	return s
}

// convertKeyValues converts protobuf key-value pairs, dropping entries whose
// value uses a variant this build does not know.
func convertKeyValues(src []*commonpb.KeyValue) []attribute.KeyValue {
	attrs := make([]attribute.KeyValue, 0, len(src))
	for _, kv := range src {
		if v, ok := convertAnyValue(kv.GetValue()); ok {
			attrs = append(attrs, attribute.KeyValue{Key: attribute.Key(kv.GetKey()), Value: v})
		}
	}
	return attrs
}

// convertAnyValue converts a commonpb.AnyValue to an attribute.Value. Returns
// (_, false) only for variants this build does not know.
func convertAnyValue(src *commonpb.AnyValue) (attribute.Value, bool) {
	switch v := src.GetValue().(type) {
	case nil:
		// "It is valid for all values to be unspecified in which case this
		// AnyValue is considered to be empty" -- OTLP common.proto. Preserved
		// as an EMPTY attribute.Value so the key survives.
		return attribute.Value{}, true
	case *commonpb.AnyValue_StringValue:
		return attribute.StringValue(v.StringValue), true
	case *commonpb.AnyValue_BoolValue:
		return attribute.BoolValue(v.BoolValue), true
	case *commonpb.AnyValue_IntValue:
		return attribute.Int64Value(v.IntValue), true
	case *commonpb.AnyValue_DoubleValue:
		return attribute.Float64Value(v.DoubleValue), true
	case *commonpb.AnyValue_BytesValue:
		return attribute.ByteSliceValue(v.BytesValue), true
	case *commonpb.AnyValue_ArrayValue:
		values := v.ArrayValue.GetValues()
		items := make([]attribute.Value, 0, len(values))
		for _, item := range values {
			if itemVal, ok := convertAnyValue(item); ok {
				items = append(items, itemVal)
			}
		}
		return attribute.SliceValue(items...), true
	case *commonpb.AnyValue_KvlistValue:
		return attribute.MapValue(convertKeyValues(v.KvlistValue.GetValues())...), true
	default:
		// Reachable only against a newer OTLP build. Debug, not Warn: this runs
		// per attribute on every read, so a skewed peer would flood the log.
		log.Debugf("convertAnyValue: unknown AnyValue variant %T, dropping", v)
		return attribute.Value{}, false
	}
}

// EnvVarNames returns the environment variables used to derive process
// context resource attributes.
func EnvVarNames() []string {
	return []string{svcNameKey, resourceAttrKey}
}

// withMergedEnvVars returns process context with attributes derived from
// OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES merged into its resource
// attributes.
func withMergedEnvVars(info Info, envVars map[libpf.String]libpf.String) Info {
	env, err := attributesFromEnvVars(envVars)
	if err != nil {
		log.Debugf("Partial resource attributes: %v", err)
	}
	// Guards live here, not in mergeAttributes: NewMergeIterator takes pointers,
	// so entering it moves both sets to the heap even on an early return.
	switch {
	case env.Len() == 0:
	case info.ResourceAttrs.Len() == 0:
		info.ResourceAttrs = env
	default:
		info.ResourceAttrs = mergeAttributes(info.ResourceAttrs, env)
	}
	return info
}

// attributesFromEnvVars builds resource attributes from OTEL_SERVICE_NAME and
// OTEL_RESOURCE_ATTRIBUTES, returning an empty set when neither contributes.
// A non-nil error means the returned set is partial.
func attributesFromEnvVars(envVars map[libpf.String]libpf.String) (attribute.Set, error) {
	var attrs []attribute.KeyValue
	var err error
	if v, ok := envVars[libpf.Intern(resourceAttrKey)]; ok {
		var pairs []attribute.KeyValue
		pairs, err = parseResourceAttributes(v.String())
		if err != nil {
			err = fmt.Errorf("%s=%q: %w", resourceAttrKey, v.String(), err)
		}
		attrs = append(attrs, pairs...)
	}
	// Appended last so it wins newAttributeSet's last-value-wins dedup:
	// OTEL_SERVICE_NAME overrides service.name from OTEL_RESOURCE_ATTRIBUTES.
	if v, ok := envVars[libpf.Intern(svcNameKey)]; ok {
		if name := strings.TrimSpace(v.String()); name != "" {
			attrs = append(attrs, semconv.ServiceName(name))
		}
	}
	return newAttributeSet(attrs), err
}

// mergeAttributes returns primary's attributes plus any keys from secondary
// not already in primary (primary wins on collision). Inputs are not modified.
func mergeAttributes(primary, secondary attribute.Set) attribute.Set {
	// Argument order is load-bearing: MergeIterator keeps the first set's
	// value on collision.
	mi := attribute.NewMergeIterator(&primary, &secondary)
	attrs := make([]attribute.KeyValue, 0, primary.Len()+secondary.Len())
	for mi.Next() {
		attrs = append(attrs, mi.Attribute())
	}
	return newAttributeSet(attrs)
}

// parseResourceAttributes parses an OTEL_RESOURCE_ATTRIBUTES value as
// comma-separated key=value pairs where keys and values are percent-encoded.
// Returns the pairs in source order, duplicates included. newAttributeSet
// resolves them last-value-wins.
//
// Malformed input yields the valid pairs plus a non-nil error. The spec says
// SHOULD discard everything, but matching the Go SDK keeps the profiler and
// the profiled application from reporting different resources.
func parseResourceAttributes(raw string) ([]attribute.KeyValue, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var pairs []attribute.KeyValue
	var errs []error
	for pair := range strings.SplitSeq(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			errs = append(errs, fmt.Errorf("missing '=' in %q", pair))
			continue
		}
		// Keep the raw text, as the Go SDK does.
		key, err := url.PathUnescape(strings.TrimSpace(k))
		if err != nil {
			key = strings.TrimSpace(k)
			errs = append(errs, fmt.Errorf("invalid key %q: %w", k, err))
		}
		value, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			value = strings.TrimSpace(v)
			errs = append(errs, fmt.Errorf("invalid value for key %q: %w", key, err))
		}
		pairs = append(pairs, attribute.String(key, value))
	}
	return pairs, errors.Join(errs...)
}
