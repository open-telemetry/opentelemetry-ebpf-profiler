// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processcontext // import "go.opentelemetry.io/ebpf-profiler/process/processcontext"

import (
	"errors"
	"fmt"
	"unicode/utf8"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	"go.opentelemetry.io/ebpf-profiler/internal/log"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
)

// Per-thread label schema, published as attributes per [OTEP 4947].
//
// [OTEP 4947]: https://github.com/open-telemetry/opentelemetry-specification/blob/main/oteps/profiles/4947-thread-ctx.md
const (
	threadCtxSchemaVersionKey       = "threadlocal.schema_version"
	supportedThreadCtxSchemaVersion = "tlsdesc_v1_dev"
	threadCtxKeyMapKey              = "threadlocal.attribute_key_map"
	// maxThreadCtxAttributeKeys is the largest key map DecodeLabels can address,
	// since it reads the key index as a single byte.
	maxThreadCtxAttributeKeys = 256
)

// threadContextInfo is one process's published per-thread label schema.
type threadContextInfo struct {
	// Indexed by the key index the payload encodes.
	attributeKeyMap []libpf.String
}

// readThreadContextInfo parses the threadlocal.* schema attributes. Returns
// (nil, nil) when no schema is published.
func readThreadContextInfo(attrs []*commonpb.KeyValue) (*threadContextInfo, error) {
	var version, keyMap *commonpb.KeyValue
	for _, attr := range attrs {
		switch attr.GetKey() {
		case threadCtxSchemaVersionKey:
			// A repeated attribute is rejected rather than merged, which would
			// shift every later key index.
			if version != nil {
				return nil, fmt.Errorf("duplicate %s attribute", threadCtxSchemaVersionKey)
			}
			version = attr
		case threadCtxKeyMapKey:
			if keyMap != nil {
				return nil, fmt.Errorf("duplicate %s attribute", threadCtxKeyMapKey)
			}
			keyMap = attr
		}
	}

	if version == nil {
		if keyMap != nil {
			return nil, errors.New("thread context attribute key map requires schema version")
		}
		// No schema published: the common case, not a fault.
		return nil, nil
	}
	if v := version.GetValue().GetStringValue(); v != supportedThreadCtxSchemaVersion {
		return nil, fmt.Errorf("unsupported thread context schema version: %s", v)
	}
	if keyMap == nil {
		return &threadContextInfo{}, nil
	}

	arrayValue := keyMap.GetValue().GetArrayValue()
	if arrayValue == nil {
		return nil, errors.New("thread context attribute key map is not an array")
	}
	values := arrayValue.GetValues()
	// Truncate rather than reject: the excess entries are already unusable.
	if len(values) > maxThreadCtxAttributeKeys {
		log.Debugf("thread context: attribute key map has %d entries, truncating to %d",
			len(values), maxThreadCtxAttributeKeys)
		values = values[:maxThreadCtxAttributeKeys]
	}
	attributeKeyMap := make([]libpf.String, 0, len(values))
	for i, item := range values {
		stringValue := item.GetStringValue()
		if stringValue == "" {
			return nil, fmt.Errorf("invalid thread context attribute at index %d: %.200s",
				i, item.String())
		}
		attributeKeyMap = append(attributeKeyMap, libpf.Intern(stringValue))
	}
	return &threadContextInfo{attributeKeyMap: attributeKeyMap}, nil
}

// DecodeLabels resolves each entry's key index against the published schema.
// Payload is repeated (key index byte, value length byte, value bytes).
func (t *threadContextInfo) DecodeLabels(data []byte) (labels map[libpf.String]libpf.String, dropped int) {
	for len(data) > 0 {
		if len(data) < 2 {
			dropped++
			break
		}
		keyIndex := int(data[0])
		valueLen := int(data[1])
		if len(data) < 2+valueLen {
			dropped++
			break
		}
		val := data[2 : 2+valueLen]
		data = data[2+valueLen:]
		if keyIndex >= len(t.attributeKeyMap) {
			dropped++
			continue
		}
		// valueLen already bounds val to what the publisher declared, so an
		// invalid value is a publisher bug, not a truncated read: drop it
		// rather than present a possibly nonsensical partial string.
		if !utf8.Valid(val) {
			dropped++
			log.Debugf("thread context: dropping invalid UTF-8 value for %q: %q",
				t.attributeKeyMap[keyIndex], val)
			continue
		}
		if labels == nil {
			labels = make(map[libpf.String]libpf.String)
		}
		key := t.attributeKeyMap[keyIndex]
		// A repeated key index means the payload is malformed: still decode it
		// (last write wins) but count it, rather than silently discard a value.
		if prev, exists := labels[key]; exists {
			dropped++
			log.Debugf("thread context: duplicate entry for %q, replacing %q with %q",
				key, prev, val)
		}
		// Interning copies val, satisfying LabelDecoder's no-alias contract.
		labels[key] = libpf.Intern(pfunsafe.ToString(val))
	}
	return labels, dropped
}

// LabelDecoder returns a decoder for the process's per-thread labels, or nil if
// it publishes no schema.
func (i Info) LabelDecoder() libpf.LabelDecoder {
	if i.threadCtx == nil {
		// Returning i.threadCtx directly would hand back a non-nil interface
		// holding a typed nil, which a caller's nil test would not catch.
		return nil
	}
	return i.threadCtx
}
