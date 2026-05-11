// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processcontext // import "go.opentelemetry.io/ebpf-profiler/processcontext"

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"structs"
	"unsafe"

	"go.opentelemetry.io/collector/pdata/pcommon"
	semconv "go.opentelemetry.io/otel/semconv/v1.34.0"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
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

	// resourceAttrKey is the environment variable name OpenTelemetry Resource information will be read from.
	resourceAttrKey = "OTEL_RESOURCE_ATTRIBUTES"

	// svcNameKey is the environment variable name that Service Name information will be read from.
	svcNameKey = "OTEL_SERVICE_NAME"

	threadCtxSchemaVersionKey       = "threadlocal.schema_version"
	supportedThreadCtxSchemaVersion = "tlsdesc_v1_dev"
	threadCtxKeyMapKey              = "threadlocal.attribute_key_map"
)

var (
	// ErrInvalidContext indicates the ProcessContext has invalid format, signature, version, or size.
	ErrInvalidContext = errors.New("invalid ProcessContext")

	// ErrConcurrentUpdate indicates the ProcessContext was updated during read.
	ErrConcurrentUpdate = errors.New("concurrent ProcessContext update detected")

	// ErrNoUpdate indicates the ProcessContext has not been updated since it was last published.
	ErrNoUpdate = errors.New("ProcessContext has not been updated")

	// ErrThreadContextInfoNotFound indicates the thread context info was not found.
	ErrThreadContextInfoNotFound = errors.New("thread context info not found")
)

type AttributeKeyMap []libpf.String

type ThreadContextInfo struct {
	schemaVersion   string
	attributeKeyMap AttributeKeyMap
}

// Info is a snapshot of process context. The pointed-to Resource and
// ExtraAttributes are shared by pointer across goroutines (process-manager
// writer, tracer, reporter) without locking; once an Info is published they
// MUST be treated as read-only by all holders.
type Info struct {
	Resource        *pcommon.Resource
	ExtraAttributes *pcommon.Map
	ThreadContext   *ThreadContextInfo
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

	ctx := processcontextpb.ProcessContext{}
	if err := proto.Unmarshal(payloadBytes, &ctx); err != nil {
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
	if ctx.ExtraAttributes != nil {
		m := pcommon.NewMap()
		for _, attr := range ctx.ExtraAttributes {
			if v, ok := convertAnyValue(attr.Value); ok {
				v.MoveTo(m.PutEmpty(attr.Key))
			}
		}
		extraAttributes = &m
	}

	threadCtx, err := readThreadContextInfo(ctx.ExtraAttributes)
	if err != nil && !errors.Is(err, ErrThreadContextInfoNotFound) {
		log.Debugf("failed to read thread context: %v", err)
	}

	return Info{
		Resource:        resource,
		ExtraAttributes: extraAttributes,
		ThreadContext:   threadCtx,
		PublishedAtNs:   hdr.MonotonicPublishedAtNs,
	}, nil
}

// convertAnyValue converts a commonpb.AnyValue to a pcommon.Value, handling
// all value types including nested maps and arrays. Returns (_, false) for
// nil inputs and unknown variants so callers can skip them rather than
// emit phantom empty entries.
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

func readThreadContextInfo(extraAttributes []*commonpb.KeyValue) (*ThreadContextInfo, error) {
	var attributeKeyMap AttributeKeyMap
	var schemaVersion string
	for _, attr := range extraAttributes {
		switch attr.Key {
		case threadCtxSchemaVersionKey:
			schemaVersion = attr.Value.GetStringValue()
			if schemaVersion != supportedThreadCtxSchemaVersion {
				return nil, fmt.Errorf("unsupported thread context schema version: %s", attr.Value.String())
			}
		case threadCtxKeyMapKey:
			arrayValue := attr.Value.GetArrayValue()
			if arrayValue == nil {
				return nil, fmt.Errorf("thread context attribute key map is not an array")
			}
			for _, item := range arrayValue.Values {
				stringValue := item.GetStringValue()
				if stringValue == "" {
					return nil, fmt.Errorf("invalid thread context attribute: %s", attr.Value.String())
				}
				attributeKeyMap = append(attributeKeyMap, libpf.Intern(stringValue))
			}
		}
	}
	if schemaVersion == "" {
		return nil, ErrThreadContextInfoNotFound
	}
	return &ThreadContextInfo{schemaVersion: schemaVersion, attributeKeyMap: attributeKeyMap}, nil
}

func (t *ThreadContextInfo) GetSchemaVersion() string {
	return t.schemaVersion
}

func (t *ThreadContextInfo) DecodeThreadLabels(data []byte) map[libpf.String]libpf.String {
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

func (p *Info) DecodeThreadLabels(data []byte) map[libpf.String]libpf.String {
	if p.ThreadContext == nil {
		return nil
	}
	return p.ThreadContext.DecodeThreadLabels(data)
}

func (p *Info) ClearThreadContextInfo() {
	p.ThreadContext = nil
}

// WithMergedEnvVars returns process context with attributes derived from
// OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES merged into its Resource.
func WithMergedEnvVars(info Info, envVars map[libpf.String]libpf.String) Info {
	info.Resource = mergeResources(info.Resource, resourceFromEnvVars(envVars))
	return info
}

// resourceFromEnvVars builds a Resource from OTEL_SERVICE_NAME and
// OTEL_RESOURCE_ATTRIBUTES, returning nil when neither yields any attribute.
func resourceFromEnvVars(envVars map[libpf.String]libpf.String) *pcommon.Resource {
	r := pcommon.NewResource()
	if v, ok := envVars[libpf.Intern(resourceAttrKey)]; ok {
		pairs, err := parseResourceAttributes(v.String())
		if err != nil {
			log.Debugf("OTEL_RESOURCE_ATTRIBUTES=%q: discarding invalid value: %v", v.String(), err)
		} else {
			for _, p := range pairs {
				r.Attributes().PutStr(p.key, p.value)
			}
		}
	}
	if v, ok := envVars[libpf.Intern(svcNameKey)]; ok {
		r.Attributes().PutStr(string(semconv.ServiceNameKey), v.String())
	}
	if r.Attributes().Len() == 0 {
		return nil
	}
	return &r
}

// mergeResources returns a Resource with primary's attributes plus any keys
// from secondary not already in primary (primary wins on collision). Returns
// nil only when both inputs are nil. Inputs are not modified.
func mergeResources(primary, secondary *pcommon.Resource) *pcommon.Resource {
	if primary == nil {
		return secondary
	}
	if secondary == nil {
		return primary
	}
	r := pcommon.NewResource()
	primary.Attributes().CopyTo(r.Attributes())
	secondary.Attributes().Range(func(k string, v pcommon.Value) bool {
		if _, exists := r.Attributes().Get(k); !exists {
			v.CopyTo(r.Attributes().PutEmpty(k))
		}
		return true
	})
	return &r
}

// resourceAttribute is one parsed entry from OTEL_RESOURCE_ATTRIBUTES.
type resourceAttribute struct {
	key, value string
}

// parseResourceAttributes parses an OTEL_RESOURCE_ATTRIBUTES value as
// comma-separated key=value pairs where keys and values are percent-encoded.
// Returns the pairs in source order; the caller dedups via last-writer-wins.
// On any decoding error the whole value is discarded per OTel spec and a
// non-nil error is returned.
func parseResourceAttributes(raw string) ([]resourceAttribute, error) {
	if raw == "" {
		return nil, nil
	}
	var pairs []resourceAttribute
	for pair := range strings.SplitSeq(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			return nil, fmt.Errorf("missing '=' in %q", pair)
		}
		key, err := url.PathUnescape(strings.TrimSpace(k))
		if err != nil {
			return nil, fmt.Errorf("invalid key %q: %w", k, err)
		}
		value, err := url.PathUnescape(strings.TrimSpace(v))
		if err != nil {
			return nil, fmt.Errorf("invalid value for key %q: %w", key, err)
		}
		pairs = append(pairs, resourceAttribute{key, value})
	}
	return pairs, nil
}

// ResourceToContextKey returns a stable key derived from the
// (service.namespace, service.name, service.instance.id) triplet which the
// OTel semantic conventions describe as globally unique for a service
// instance.
// See: https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/service.md
//
// Returns libpf.NullString only when resource is nil or none of the three
// attributes is present. When at least one is present, the result joins all
// three with ':' (missing components render as empty strings); callers
// should treat the null sentinel as "unidentifiable" and may choose to
// group such samples by other fields.
func ResourceToContextKey(resource *pcommon.Resource) libpf.String {
	if resource == nil {
		return libpf.NullString
	}
	serviceNamespace, namespaceOk := resource.Attributes().Get(string(semconv.ServiceNamespaceKey))
	serviceName, nameOk := resource.Attributes().Get(string(semconv.ServiceNameKey))
	serviceInstanceID, instanceIdOk := resource.Attributes().Get(string(semconv.ServiceInstanceIDKey))
	// If all three attributes are missing, return an empty string instead of ":::" to ensure that nil resource
	// and empty resource are treated as the same.
	if !namespaceOk && !nameOk && !instanceIdOk {
		return libpf.NullString
	}
	return libpf.Intern(fmt.Sprintf("%s:%s:%s",
		serviceNamespace.Str(), serviceName.Str(), serviceInstanceID.Str()))
}
