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

	// Per-thread label schema, published as attributes per [OTEP 4719].
	threadCtxSchemaVersionKey       = "threadlocal.schema_version"
	supportedThreadCtxSchemaVersion = "tlsdesc_v1_dev"
	threadCtxKeyMapKey              = "threadlocal.attribute_key_map"
)

var (
	// errInvalidContext indicates the ProcessContext has invalid format, signature, version, or size.
	errInvalidContext = errors.New("invalid ProcessContext")

	// errConcurrentUpdate indicates the ProcessContext was updated during read.
	errConcurrentUpdate = errors.New("concurrent ProcessContext update detected")

	// errNoUpdate indicates the ProcessContext has not been updated since it was last published.
	errNoUpdate = errors.New("ProcessContext has not been updated")

	// errThreadContextInfoNotFound is the common case: most processes publish
	// a context without a thread-label schema.
	errThreadContextInfoNotFound = errors.New("thread context info not found")
)

// threadContextInfo is one process's published per-thread label schema.
type threadContextInfo struct {
	schemaVersion string
	// Indexed by the key index the payload encodes.
	attributeKeyMap []libpf.String
}

var _ libpf.LabelDecoder = (*threadContextInfo)(nil)

// Info is a snapshot of process context. Copies are safe to share across
// goroutines: attribute.Set is immutable and threadCtx is never mutated after
// construction.
type Info struct {
	ResourceAttrs attribute.Set
	threadCtx     *threadContextInfo
	publishedAtNs uint64
	// resolved is false only on a zero Info, meaning never resolved or
	// invalidated by an exec. Resolve never returns an unresolved Info.
	resolved bool
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

	ctx, threadCtxErr, ctxErr := readPayload(rm, hdr)
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

	if threadCtxErr != nil {
		// The read is now known coherent, so this is a real fault (unsupported
		// schema version, or a malformed publisher) rather than a torn read.
		// Every native label from this process is dropped until it is fixed.
		log.Warnf("failed to read thread context: %v", threadCtxErr)
	}

	return ctx, nil
}

// Resolve reads the process context from a context mapping (if any). Per
// [OTEP 4719], a successful read is already the SDK's resolved resource, so
// it publishes as-is. OTEL_SERVICE_NAME/OTEL_RESOURCE_ATTRIBUTES are only a
// fallback when no context is available.
// Returns old when nothing new was read, so the result is always safe to store.
//
// mappingAddr=0 means the mapping was not observed this sync. Pass a zero old
// to force a rebuild, which is what an exec requires so that new env vars take
// effect even while a mapping is present.
func Resolve(
	mappingAddr uint64, pid libpf.PID, rm remotememory.RemoteMemory,
	old Info,
	envVars map[libpf.String]libpf.String,
) Info {
	if mappingAddr == 0 {
		// Old came from env vars alone: nothing changed.
		if old.resolved && old.publishedAtNs == 0 {
			return old
		}
	} else {
		// Workaround for a CodeQL warning about uint64 -> uintptr (libpf.Address) overflow.
		addr := libpf.Address(mappingAddr & uint64(^libpf.Address(0)))

		ctx, err := read(addr, rm, old.publishedAtNs, 0)
		switch {
		case err == nil:
			ctx.resolved = true
			return ctx
		case errors.Is(err, errNoUpdate):
			return old
		case errors.Is(err, errConcurrentUpdate):
			// Retries are exhausted, so prefer the previous context over dropping it.
			if old.resolved {
				return old
			}
		default:
			log.Debugf("Failed to read ProcessContext for PID %d: %v", pid, err)
		}
	}

	// No context to read from at this point, so env vars are all there is.
	env, err := attributesFromEnvVars(envVars)
	if err != nil {
		log.Debugf("Partial resource attributes: %v", err)
	}
	return Info{ResourceAttrs: env, resolved: true}
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

// threadCtxErr reports a non-fatal thread-context schema fault: Info is valid
// without it. Returned rather than logged here because only the caller's
// timestamp recheck can tell a genuine fault from a torn read.
func readPayload(rm remotememory.RemoteMemory, hdr header,
) (info Info, threadCtxErr error, err error) {
	payloadBytes := make([]byte, hdr.PayloadSize)
	if err := rm.Read(libpf.Address(hdr.PayloadPtr), payloadBytes); err != nil {
		return Info{}, nil, fmt.Errorf("failed to read payload: %w", err)
	}

	ctx := &processcontextpb.ProcessContext{}
	if err := proto.Unmarshal(payloadBytes, ctx); err != nil {
		return Info{}, nil, fmt.Errorf("failed to unmarshal ProcessContext: %w", err)
	}

	threadCtx, threadCtxErr := readThreadContextInfo(ctx.GetAttributes())
	if errors.Is(threadCtxErr, errThreadContextInfoNotFound) {
		// No schema published: the common case, not a fault.
		threadCtxErr = nil
	}

	return Info{
		ResourceAttrs: newAttributeSet(convertKeyValues(ctx.GetResource().GetAttributes())),
		threadCtx:     threadCtx,
		publishedAtNs: hdr.MonotonicPublishedAtNs,
	}, threadCtxErr, nil
}

// readThreadContextInfo parses the threadlocal.* schema attributes. Returns
// errThreadContextInfoNotFound when no schema is published.
func readThreadContextInfo(attrs []*commonpb.KeyValue) (*threadContextInfo, error) {
	var attributeKeyMap []libpf.String
	var schemaVersion string
	for _, attr := range attrs {
		switch attr.GetKey() {
		case threadCtxSchemaVersionKey:
			schemaVersion = attr.GetValue().GetStringValue()
			if schemaVersion != supportedThreadCtxSchemaVersion {
				return nil, fmt.Errorf("unsupported thread context schema version: %s",
					attr.GetValue().String())
			}
		case threadCtxKeyMapKey:
			arrayValue := attr.GetValue().GetArrayValue()
			if arrayValue == nil {
				return nil, errors.New("thread context attribute key map is not an array")
			}
			for _, item := range arrayValue.GetValues() {
				stringValue := item.GetStringValue()
				if stringValue == "" {
					return nil, fmt.Errorf("invalid thread context attribute: %s", attr.GetValue().String())
				}
				attributeKeyMap = append(attributeKeyMap, libpf.Intern(stringValue))
			}
		}
	}
	if schemaVersion == "" {
		return nil, errThreadContextInfoNotFound
	}
	return &threadContextInfo{schemaVersion: schemaVersion, attributeKeyMap: attributeKeyMap}, nil
}

// DecodeLabels resolves each entry's key index against the published schema.
// Payload is repeated (key index byte, value length byte, value bytes).
func (t *threadContextInfo) DecodeLabels(data []byte) map[libpf.String]libpf.String {
	labels := make(map[libpf.String]libpf.String)
	for len(data) >= 2 {
		keyIndex := int(data[0])
		valueLen := int(data[1])
		if len(data) < 2+valueLen {
			break
		}
		val := data[2 : 2+valueLen]
		valStr := libpf.Intern(pfunsafe.ToString(val))
		data = data[2+valueLen:]
		if keyIndex >= len(t.attributeKeyMap) {
			continue
		}
		labels[t.attributeKeyMap[keyIndex]] = valStr
	}
	return labels
}

// LabelDecoder returns a decoder for the process's per-thread labels, or nil if
// it publishes no schema.
//
// The explicit nil check keeps this from returning a non-nil interface holding
// a typed nil, which a caller's nil test would not catch.
func (i Info) LabelDecoder() libpf.LabelDecoder {
	if i.threadCtx == nil {
		return nil
	}
	return i.threadCtx
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

// EnvVarSet returns the environment variables used to derive process context
// resource attributes.
func EnvVarSet() libpf.Set[string] {
	return libpf.Set[string]{svcNameKey: {}, resourceAttrKey: {}}
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
