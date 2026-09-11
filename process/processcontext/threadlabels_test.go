// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processcontext

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func strVal(s string) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: s}}
}

func attr(k string, v *commonpb.AnyValue) *commonpb.KeyValue {
	return &commonpb.KeyValue{Key: k, Value: v}
}

func arrVal(vals ...*commonpb.AnyValue) *commonpb.AnyValue {
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{
		ArrayValue: &commonpb.ArrayValue{Values: vals},
	}}
}

func manyStrVals(n int) []*commonpb.AnyValue {
	vals := make([]*commonpb.AnyValue, n)
	for i := range vals {
		vals[i] = strVal(fmt.Sprintf("k%d", i))
	}
	return vals
}

func manyLibpfStrings(n int) []libpf.String {
	strs := make([]libpf.String, n)
	for i := range strs {
		strs[i] = libpf.Intern(fmt.Sprintf("k%d", i))
	}
	return strs
}

func TestReadThreadContextInfo(t *testing.T) {
	version := attr(threadCtxSchemaVersionKey, strVal(supportedThreadCtxSchemaVersion))

	tests := map[string]struct {
		attrs        []*commonpb.KeyValue
		wantKeyMap   []libpf.String
		wantNoSchema bool
		wantErrSub   string
	}{
		"no threadlocal attributes": {
			attrs:        []*commonpb.KeyValue{attr("custom.attribute", strVal("v"))},
			wantNoSchema: true,
		},
		// A key map alone is invalid: without a version the encoding is unknown.
		"key map without a version": {
			attrs:      []*commonpb.KeyValue{attr(threadCtxKeyMapKey, arrVal(strVal("a")))},
			wantErrSub: "requires schema version",
		},
		"version without a key map": {
			attrs:      []*commonpb.KeyValue{version},
			wantKeyMap: nil,
		},
		"version and key map": {
			attrs: []*commonpb.KeyValue{
				version,
				attr(threadCtxKeyMapKey, arrVal(strVal("a"), strVal("b"))),
			},
			wantKeyMap: []libpf.String{libpf.Intern("a"), libpf.Intern("b")},
		},
		"key map before version": {
			attrs: []*commonpb.KeyValue{
				attr(threadCtxKeyMapKey, arrVal(strVal("a"))),
				version,
			},
			wantKeyMap: []libpf.String{libpf.Intern("a")},
		},
		"unsupported version": {
			attrs:      []*commonpb.KeyValue{attr(threadCtxSchemaVersionKey, strVal("v99"))},
			wantErrSub: "unsupported thread context schema version",
		},
		"key map is not an array": {
			attrs:      []*commonpb.KeyValue{version, attr(threadCtxKeyMapKey, strVal("a"))},
			wantErrSub: "not an array",
		},
		// GetStringValue on a non-string AnyValue also returns "", so this
		// covers a non-string entry too: same branch, no separate case needed.
		"key map holds an empty key": {
			attrs: []*commonpb.KeyValue{
				version,
				attr(threadCtxKeyMapKey, arrVal(strVal("a"), strVal(""))),
			},
			wantErrSub: "invalid thread context attribute",
		},
		"duplicate version attribute": {
			attrs:      []*commonpb.KeyValue{version, version},
			wantErrSub: "duplicate",
		},
		"duplicate key map attribute": {
			attrs: []*commonpb.KeyValue{
				version,
				attr(threadCtxKeyMapKey, arrVal(strVal("a"))),
				attr(threadCtxKeyMapKey, arrVal(strVal("b"))),
			},
			wantErrSub: "duplicate",
		},
		"key map exceeds byte-addressable range": {
			attrs: []*commonpb.KeyValue{
				version,
				attr(threadCtxKeyMapKey, arrVal(manyStrVals(maxThreadCtxAttributeKeys+1)...)),
			},
			wantKeyMap: manyLibpfStrings(maxThreadCtxAttributeKeys),
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := readThreadContextInfo(tt.attrs)

			switch {
			case tt.wantNoSchema:
				require.NoError(t, err)
				assert.Nil(t, got)
			case tt.wantErrSub == "":
				require.NoError(t, err)
				require.NotNil(t, got)
				assert.Equal(t, tt.wantKeyMap, got.attributeKeyMap)
			default:
				require.Error(t, err)
				assert.Nil(t, got)
				assert.Contains(t, err.Error(), tt.wantErrSub)
			}
		})
	}
}

// Callers test the result against nil, so a nil schema must not surface as a
// non-nil interface holding a typed nil.
func TestInfoLabelDecoder_NilSchema(t *testing.T) {
	assert.Nil(t, Info{}.LabelDecoder())
}

func TestDecodeLabels(t *testing.T) {
	keyMap := []libpf.String{
		libpf.Intern("http_route"),
		libpf.Intern("http_method"),
		libpf.Intern("user_id"),
	}

	// entryRaw encodes one (key index, value length, value) tuple.
	entryRaw := func(keyIndex byte, value []byte) []byte {
		return append([]byte{keyIndex, byte(len(value))}, value...)
	}
	entry := func(keyIndex byte, value string) []byte {
		return entryRaw(keyIndex, []byte(value))
	}

	tests := map[string]struct {
		data        []byte
		want        map[string]string
		wantDropped int
	}{
		"empty payload": {
			data: nil,
			want: nil,
		},
		// The length prefix counts bytes, not runes.
		"multi-byte value": {
			data: entry(0, "/健康"),
			want: map[string]string{"http_route": "/健康"},
		},
		"entries resolve by index, not order": {
			data: append(append(entry(2, "u-1"), entry(1, "GET")...), entry(0, "/x")...),
			want: map[string]string{"user_id": "u-1", "http_method": "GET", "http_route": "/x"},
		},
		"empty value is kept": {
			data: entry(1, ""),
			want: map[string]string{"http_method": ""},
		},
		// A key index the published map does not cover cannot be named, but it
		// carries a length so the entries after it stay decodable.
		"unknown key index is skipped and counted as dropped": {
			data:        append(append(entry(9, "dropped"), entry(1, "GET")...), entry(0, "/y")...),
			want:        map[string]string{"http_method": "GET", "http_route": "/y"},
			wantDropped: 1,
		},
		// Truncation must stop decoding rather than read past the payload, and
		// must count as dropped so it's not indistinguishable from a clean end.
		"value length past end of payload": {
			data:        append(entry(0, "/x"), 1, 40, 'G', 'E', 'T'),
			want:        map[string]string{"http_route": "/x"},
			wantDropped: 1,
		},
		"trailing byte without a length": {
			data:        append(entry(0, "/x"), 1),
			want:        map[string]string{"http_route": "/x"},
			wantDropped: 1,
		},
		// valueLen already bounds the value, so this is a publisher bug, not a
		// truncated read: the whole entry is dropped rather than salvaged.
		"invalid UTF-8 value is dropped, siblings kept": {
			data:        append(entryRaw(0, []byte{0xff}), entry(1, "GET")...),
			want:        map[string]string{"http_method": "GET"},
			wantDropped: 1,
		},
		// A repeated key index is malformed, so the earlier value is counted as
		// dropped even though the entry itself decodes (last write wins).
		"duplicate key index counts the overwritten value as dropped": {
			data:        append(entry(0, "/x"), entry(0, "/y")...),
			want:        map[string]string{"http_route": "/y"},
			wantDropped: 1,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			tc := &threadContextInfo{attributeKeyMap: keyMap}

			got, dropped := tc.DecodeLabels(tt.data)

			// A nil map isn't allocated until the first label is kept.
			var want map[libpf.String]libpf.String
			if len(tt.want) > 0 {
				want = make(map[libpf.String]libpf.String, len(tt.want))
				for k, v := range tt.want {
					want[libpf.Intern(k)] = libpf.Intern(v)
				}
			}
			assert.Equal(t, want, got)
			assert.Equal(t, tt.wantDropped, dropped)
		})
	}
}

// The decoder must not retain the eBPF payload, which is reused per trace.
// Interning is what breaks ToString's alias, so this guards a decode path that
// stopped interning.
func TestDecodeLabelsDoesNotAliasPayload(t *testing.T) {
	tc := &threadContextInfo{
		attributeKeyMap: []libpf.String{libpf.Intern("k")},
	}

	data := append([]byte{0, 3}, "abc"...)
	got, _ := tc.DecodeLabels(data)
	require.Equal(t, libpf.Intern("abc"), got[libpf.Intern("k")])

	copy(data[2:], "xyz")
	assert.Equal(t, libpf.Intern("abc"), got[libpf.Intern("k")],
		"decoded value must not alias the caller's buffer")
}
