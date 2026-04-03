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
	Resource        *pcommon.Resource
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
			convertAnyValue(attr.Value).MoveTo(r.Attributes().PutEmpty(attr.Key))
		}
		resource = &r
	}

	var extraAttributes *pcommon.Map
	if ctx.ExtraAttributes != nil {
		m := pcommon.NewMap()
		for _, attr := range ctx.ExtraAttributes {
			convertAnyValue(attr.Value).MoveTo(m.PutEmpty(attr.Key))
		}
		extraAttributes = &m
	}
	return Info{Resource: resource, ExtraAttributes: extraAttributes, PublishedAtNs: hdr.MonotonicPublishedAtNs}, nil
}

func (p *Info) ClearExtraAttributes() {
	// if p.Context != nil {
	// 	p.Context.ExtraAttributes = nil
	// }
}

// convertAnyValue converts a commonpb.AnyValue to a pcommon.Value,
// handling all value types including nested maps and arrays.
func convertAnyValue(src *commonpb.AnyValue) pcommon.Value {
	if src == nil {
		return pcommon.NewValueEmpty()
	}
	switch v := src.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return pcommon.NewValueStr(v.StringValue)
	case *commonpb.AnyValue_BoolValue:
		return pcommon.NewValueBool(v.BoolValue)
	case *commonpb.AnyValue_IntValue:
		return pcommon.NewValueInt(v.IntValue)
	case *commonpb.AnyValue_DoubleValue:
		return pcommon.NewValueDouble(v.DoubleValue)
	case *commonpb.AnyValue_BytesValue:
		val := pcommon.NewValueBytes()
		val.Bytes().FromRaw(v.BytesValue)
		return val
	case *commonpb.AnyValue_ArrayValue:
		val := pcommon.NewValueSlice()
		if v.ArrayValue != nil {
			sl := val.Slice()
			sl.EnsureCapacity(len(v.ArrayValue.Values))
			for _, item := range v.ArrayValue.Values {
				convertAnyValue(item).MoveTo(sl.AppendEmpty())
			}
		}
		return val
	case *commonpb.AnyValue_KvlistValue:
		val := pcommon.NewValueMap()
		if v.KvlistValue != nil {
			m := val.Map()
			m.EnsureCapacity(len(v.KvlistValue.Values))
			for _, kv := range v.KvlistValue.Values {
				convertAnyValue(kv.Value).MoveTo(m.PutEmpty(kv.Key))
			}
		}
		return val
	default:
		return pcommon.NewValueEmpty()
	}
}

func (p *Info) addResourceStringAttribute(key string, value string) {
	if p.Resource == nil {
		r := pcommon.NewResource()
		p.Resource = &r
	}
	// Only add the attribute if it is not already present.
	if _, ok := p.Resource.Attributes().Get(key); ok {
		return
	}
	p.Resource.Attributes().PutStr(key, value)
}

// AddEnvVars adds the given env vars to the ProcessContext as resource attributes.
// OTEL_SERVICE_NAME is mapped to the service.name attribute.
// OTEL_RESOURCE_ATTRIBUTES is parsed as comma-separated key=value pairs with
// percent-encoded keys and values per the OTel resource SDK specification.
// OTEL_SERVICE_NAME takes precedence over service.name in OTEL_RESOURCE_ATTRIBUTES.
func (p *Info) AddEnvVars(envVars map[libpf.String]libpf.String) {
	// Process OTEL_SERVICE_NAME first so it takes precedence over any
	// service.name key inside OTEL_RESOURCE_ATTRIBUTES (addResourceAttribute
	// skips keys that are already present).
	if value, ok := envVars[libpf.Intern(svcNameKey)]; ok {
		p.addResourceStringAttribute(string(semconv.ServiceNameKey), value.String())
	}
	if value, ok := envVars[libpf.Intern(resourceAttrKey)]; ok {
		p.parseResourceAttributes(value.String())
	}
}

// parseResourceAttributes parses the OTEL_RESOURCE_ATTRIBUTES env var value
// as comma-separated key=value pairs where keys and values are percent-encoded.
// On any decoding error the entire value is discarded.
func (p *Info) parseResourceAttributes(raw string) {
	if raw == "" {
		return
	}
	// Parse into a temporary slice first so that on error we discard everything
	// per the OTel spec.
	type kv struct{ key, value string }
	var pairs []kv
	for pair := range strings.SplitSeq(raw, ",") {
		k, v, ok := strings.Cut(pair, "=")
		if !ok {
			log.Debugf("OTEL_RESOURCE_ATTRIBUTES: discarding invalid value: missing '=' in %q", pair)
			return
		}
		key, err := url.PathUnescape(k)
		if err != nil {
			log.Debugf("OTEL_RESOURCE_ATTRIBUTES: discarding invalid value: %v", err)
			return
		}
		value, err := url.PathUnescape(v)
		if err != nil {
			log.Debugf("OTEL_RESOURCE_ATTRIBUTES: discarding invalid value: %v", err)
			return
		}
		pairs = append(pairs, kv{key, value})
	}
	for _, pair := range pairs {
		p.addResourceStringAttribute(pair.key, pair.value)
	}
}

func ResourceToContextKey(resource *pcommon.Resource) libpf.String {
	if resource == nil {
		return libpf.NullString
	}
	// Per semantic conventions, triplet of service.namespace, service.name, service.instance.id
	// must be globally unique.
	// https://github.com/open-telemetry/semantic-conventions/blob/main/docs/registry/attributes/service.md
	serviceNamespace, namespaceOk := resource.Attributes().Get(string(semconv.ServiceNamespaceKey))
	serviceName, nameOk := resource.Attributes().Get(string(semconv.ServiceNameKey))
	serviceInstanceID, instanceIdOk := resource.Attributes().Get(string(semconv.ServiceInstanceIDKey))
	if !namespaceOk || !nameOk || !instanceIdOk {
		return libpf.NullString
	}
	return libpf.Intern(fmt.Sprintf("%s:%s:%s", serviceNamespace.Str(), serviceName.Str(), serviceInstanceID.Str()))
}
