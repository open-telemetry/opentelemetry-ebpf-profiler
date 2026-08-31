// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux && (amd64 || arm64)

package processcontext

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	processcontextpb "go.opentelemetry.io/proto/otlp/processcontext/v1development"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

var testContext = processcontextpb.ProcessContext{
	Resource: &resourcepb.Resource{
		Attributes: []*commonpb.KeyValue{
			{
				Key: "service.name",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_StringValue{
						StringValue: "test-service",
					},
				},
			},
			{
				Key: "service.version",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_IntValue{
						IntValue: 42,
					},
				},
			},
			{
				Key: "service.active",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_BoolValue{
						BoolValue: true,
					},
				},
			},
			{
				Key: "service.weight",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_DoubleValue{
						DoubleValue: 3.14,
					},
				},
			},
			{
				Key: "service.tags",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_ArrayValue{
						ArrayValue: &commonpb.ArrayValue{
							Values: []*commonpb.AnyValue{
								{Value: &commonpb.AnyValue_StringValue{StringValue: "tag1"}},
								{Value: &commonpb.AnyValue_IntValue{IntValue: 2}},
							},
						},
					},
				},
			},
			{
				Key: "service.metadata",
				Value: &commonpb.AnyValue{
					Value: &commonpb.AnyValue_KvlistValue{
						KvlistValue: &commonpb.KeyValueList{
							Values: []*commonpb.KeyValue{
								{
									Key: "nested.key",
									Value: &commonpb.AnyValue{
										Value: &commonpb.AnyValue_StringValue{
											StringValue: "nested-value",
										},
									},
								},
								{
									Key: "nested.count",
									Value: &commonpb.AnyValue{
										Value: &commonpb.AnyValue_IntValue{
											IntValue: 7,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	},
	Attributes: []*commonpb.KeyValue{
		{
			Key: "custom.attribute",
			Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{
					StringValue: "custom-value",
				},
			},
		},
	},
}

// mockReader serves reads from a set of (address, bytes) regions. A read may
// not span two regions.
type mockReader struct {
	regions []mockRegion
	err     error
}

type mockRegion struct {
	addr uint64
	data []byte
}

func newMockReader() *mockReader {
	return &mockReader{}
}

func (m *mockReader) setError(err error) {
	m.err = err
}

func (m *mockReader) writeAt(addr uint64, data []byte) {
	m.regions = append(m.regions, mockRegion{addr: addr, data: append([]byte{}, data...)})
}

func (m *mockReader) ReadAt(p []byte, off int64) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}

	addr := uint64(off)
	for _, r := range m.regions {
		if addr >= r.addr && addr+uint64(len(p)) <= r.addr+uint64(len(r.data)) {
			offset := addr - r.addr
			copy(p, r.data[offset:offset+uint64(len(p))])
			return len(p), nil
		}
	}
	return 0, io.EOF
}

// createHeader serializes via the header struct itself, so a layout change in
// the reader cannot leave the fixtures producing a stale wire format.
func createHeader(signature string, version uint32, payloadSize uint32, payloadPtr uint64, publishedAt uint64) []byte {
	hdr := header{
		Version:                version,
		PayloadSize:            payloadSize,
		MonotonicPublishedAtNs: publishedAt,
		PayloadPtr:             payloadPtr,
	}
	copy(hdr.Signature[:], signature)
	return bytes.Clone(pfunsafe.FromPointer(&hdr))
}

func createValidHeader(payloadSize uint32, payloadPtr uint64, publishedAt uint64) []byte {
	return createHeader(signatureOTELCTX, supportedVersion, payloadSize, payloadPtr, publishedAt)
}

func TestProcessContext_IsContextMapping(t *testing.T) {
	assert.True(t, IsContextMapping(false, "[anon:OTEL_CTX]"))
	assert.True(t, IsContextMapping(false, "[anon_shmem:OTEL_CTX]"))
	assert.True(t, IsContextMapping(false, "/memfd:OTEL_CTX"))
	assert.True(t, IsContextMapping(false, "/memfd:OTEL_CTX (deleted)"))
	assert.False(t, IsContextMapping(false, "test"))
	assert.False(t, IsContextMapping(true, "[anon:OTEL_CTX]"))
}

func TestProcessContext_Read(t *testing.T) {
	payload, err := proto.Marshal(&testContext)
	require.NoError(t, err)

	mappingAddr := libpf.Address(0x1000)

	tests := []struct {
		name              string
		setupMock         func(*mockReader)
		expectedResult    Info
		expectedErr       error
		errorSubstring    string
		lastPublishedAtNs uint64
	}{
		{
			name: "success with valid context",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				payloadAddr := uint64(0x2000)
				header := createValidHeader(uint32(len(payload)), payloadAddr, 123456789)
				mock.writeAt(headerAddr, header)
				mock.writeAt(payloadAddr, payload)
			},
			expectedResult: Info{
				ResourceAttrs: expectedResourceAttrs(),
				attributes:    expectedAttributes(),
				publishedAtNs: 123456789,
			},
		},
		{
			name: "read error",
			setupMock: func(mock *mockReader) {
				mock.setError(errors.New("read error"))
			},
			expectedErr: errInvalidContext,
		},
		{
			name: "invalid protobuf",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				payloadAddr := uint64(0x2000)
				invalidPayload := []byte{0xff, 0xff, 0xff, 0xff}
				header := createValidHeader(uint32(len(invalidPayload)), payloadAddr, 123456789)
				mock.writeAt(headerAddr, header)
				mock.writeAt(payloadAddr, invalidPayload)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "failed to unmarshal",
		},
		{
			name: "invalid signature",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader("INVALID!", supportedVersion, 100, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "signature",
		},
		{
			name: "invalid version",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader(signatureOTELCTX, 999, 100, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "version",
		},
		{
			name: "zero payload size",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(0, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "payload size",
		},
		{
			name: "payload size too large",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader(signatureOTELCTX, supportedVersion, 1024*1024, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    errInvalidContext,
			errorSubstring: "payload size",
		},
		{
			name: "published at zero - update in progress",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(100, 0x2000, 0)
				mock.writeAt(headerAddr, header)
			},
			expectedErr: errConcurrentUpdate,
		},
		{
			name: "published at same as last published",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(100, 0x2000, 123456788)
				mock.writeAt(headerAddr, header)
			},
			lastPublishedAtNs: 123456788,
			expectedErr:       errNoUpdate,
		},
		{
			name: "published at too old",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(100, 0x2000, 123456787)
				mock.writeAt(headerAddr, header)
			},
			lastPublishedAtNs: 123456788,
			expectedErr:       errNoUpdate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReader()
			tt.setupMock(mock)

			rm := remotememory.RemoteMemory{ReaderAt: mock}

			ctx, err := read(mappingAddr, rm, tt.lastPublishedAtNs, 0)

			if tt.expectedErr == nil {
				require.NoError(t, err)
				require.Equal(t, tt.expectedResult, ctx)
			} else {
				assert.Zero(t, ctx.ResourceAttrs.Len())
				assert.Zero(t, ctx.attributes.Len())
				assert.Zero(t, ctx.publishedAtNs)
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedErr)
				if tt.errorSubstring != "" {
					assert.Contains(t, err.Error(), tt.errorSubstring)
				}
			}
		})
	}
}

func TestProcessContext_Read_RealProcessContext(t *testing.T) {
	tests := []struct {
		name     string
		useMemfd bool
		usePrctl bool
	}{
		{
			name:     "memfd only",
			useMemfd: true,
			usePrctl: false,
		},
		{
			name:     "prctl only",
			useMemfd: false,
			usePrctl: true,
		},
		{
			name:     "memfd and prctl",
			useMemfd: true,
			usePrctl: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload, err := proto.Marshal(&testContext)
			require.NoError(t, err)

			payloadAddr := libpf.Address(unsafe.Pointer(&payload[0]))
			header := createValidHeader(uint32(len(payload)), uint64(payloadAddr), 123456789)

			memSize := len(header)
			var mem []byte
			if tt.useMemfd {
				fd, err := unix.MemfdCreate(signatureOTELCTX, 0)
				require.NoError(t, err)
				defer unix.Close(fd)

				err = unix.Ftruncate(fd, int64(memSize))
				require.NoError(t, err)
				mem, err = unix.Mmap(
					fd, 0, memSize,
					unix.PROT_READ|unix.PROT_WRITE,
					unix.MAP_PRIVATE,
				)
				require.NoError(t, err)
				defer unix.Munmap(mem)
				unix.Close(fd)
			} else {
				mem, err = unix.Mmap(
					-1, 0, memSize,
					unix.PROT_READ|unix.PROT_WRITE,
					unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
				)
				require.NoError(t, err)
				defer unix.Munmap(mem)
			}

			copy(mem[0:len(header)], header)

			if tt.usePrctl {
				nameNullTerminated, _ := unix.ByteSliceFromString(signatureOTELCTX)
				err = unix.Prctl(unix.PR_SET_VMA,
					unix.PR_SET_VMA_ANON_NAME,
					uintptr(unsafe.Pointer(&mem[0])),
					uintptr(memSize),
					uintptr(unsafe.Pointer(&nameNullTerminated[0])),
				)
				if err != nil {
					t.Skipf("prctl not supported: %v", err)
				}
			}

			pid := libpf.PID(os.Getpid())
			proc := process.New(pid, pid)
			defer proc.Close()

			var contextMappingAddr uint64
			_, err = proc.IterateMappings(func(m process.RawMapping) bool {
				if IsContextMapping(m.IsExecutable(), m.Path) {
					contextMappingAddr = m.Vaddr
					return false
				}
				return true
			})
			if err != nil && !errors.Is(err, process.ErrCallbackStopped) {
				require.NoError(t, err)
			}
			require.NotZero(t, contextMappingAddr)

			result, err := read(libpf.Address(contextMappingAddr), proc.GetRemoteMemory(), 0, 0)
			require.NoError(t, err)
			require.Equal(t,
				Info{
					ResourceAttrs: expectedResourceAttrs(),
					attributes:    expectedAttributes(),
					publishedAtNs: 123456789,
				},
				result)

		})
	}
}

func expectedResourceAttrs() attribute.Set {
	return attribute.NewSet(
		attribute.String("service.name", "test-service"),
		attribute.Int64("service.version", 42),
		attribute.Bool("service.active", true),
		attribute.Float64("service.weight", 3.14),
		attribute.Slice("service.tags",
			attribute.StringValue("tag1"),
			attribute.Int64Value(2)),
		attribute.Map("service.metadata",
			attribute.String("nested.key", "nested-value"),
			attribute.Int64("nested.count", 7)),
	)
}

func expectedAttributes() attribute.Set {
	return attribute.NewSet(attribute.String("custom.attribute", "custom-value"))
}

// An AnyValue with no variant set is a valid empty value per OTLP
// common.proto. The key must survive the read with an EMPTY value rather than
// be dropped.
func TestProcessContext_Read_KeepsEmptyValues(t *testing.T) {
	payload, err := proto.Marshal(&processcontextpb.ProcessContext{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			{Key: "set", Value: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{StringValue: "v"}}},
			{Key: "unset.oneof", Value: &commonpb.AnyValue{}},
			{Key: "absent.value"},
		}},
	})
	require.NoError(t, err)

	const payloadAddr = 0x2000
	mock := newMockReader()
	mock.writeAt(0x1000, createValidHeader(uint32(len(payload)), payloadAddr, 1))
	mock.writeAt(payloadAddr, payload)

	info, err := read(libpf.Address(0x1000),
		remotememory.RemoteMemory{ReaderAt: mock}, 0, 0)
	require.NoError(t, err)

	require.Equal(t, attribute.NewSet(
		attribute.String("set", "v"),
		attribute.KeyValue{Key: "unset.oneof"},
		attribute.KeyValue{Key: "absent.value"},
	), info.ResourceAttrs)
}

func TestAttributesFromEnvVars(t *testing.T) {
	tests := []struct {
		name     string
		envVars  map[libpf.String]libpf.String
		expected map[string]string
	}{
		{
			name: "no env vars",
		},
		{
			name: "OTEL_SERVICE_NAME",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("my-service"),
			},
			expected: map[string]string{
				"service.name": "my-service",
			},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES simple",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("key1=value1,key2=value2"),
			},
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES percent-encoded values",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("key1=val%2Cwith%2Ccomma,key2=value2"),
			},
			expected: map[string]string{
				"key1": "val,with,comma",
				"key2": "value2",
			},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES percent-encoded keys",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("key%3D2=value2,key%2C3=value3"),
			},
			expected: map[string]string{
				"key=2": "value2",
				"key,3": "value3",
			},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES undecodable value kept raw, siblings kept",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,bad=%ZZ"),
			},
			expected: map[string]string{"good": "value", "bad": "%ZZ"},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES undecodable key kept raw, siblings kept",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,bad%ZZ=value2"),
			},
			expected: map[string]string{"good": "value", "bad%ZZ": "value2"},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES missing equals skips pair, siblings kept",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,badpair"),
			},
			expected: map[string]string{"good": "value"},
		},
		{
			name: "OTEL_SERVICE_NAME is trimmed",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("  my-service  "),
			},
			expected: map[string]string{"service.name": "my-service"},
		},
		{
			name: "OTEL_SERVICE_NAME whitespace only is dropped",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("   "),
			},
			expected: nil,
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES surrounding whitespace is trimmed",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("  k=v  "),
			},
			expected: map[string]string{"k": "v"},
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES empty value",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern(""),
			},
			expected: nil,
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES empty key dropped, siblings kept",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("=orphan,good=value"),
			},
			expected: map[string]string{"good": "value"},
		},
		{
			name: "both env vars",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"):        libpf.Intern("my-svc"),
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("deployment.environment=prod"),
			},
			expected: map[string]string{
				"service.name":           "my-svc",
				"deployment.environment": "prod",
			},
		},
		{
			name: "OTEL_SERVICE_NAME wins over service.name in OTEL_RESOURCE_ATTRIBUTES",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"):        libpf.Intern("from-service-name"),
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("service.name=from-attrs"),
			},
			expected: map[string]string{
				"service.name": "from-service-name",
			},
		},
		{
			// Last-writer-wins is mandated by the OTel spec, not incidental.
			name: "OTEL_RESOURCE_ATTRIBUTES duplicate keys: last writer wins",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("k=first,k=second,k=third"),
			},
			expected: map[string]string{
				"k": "third",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, _ := attributesFromEnvVars(tt.envVars)

			if tt.expected == nil {
				assert.Zero(t, attrs.Len())
				return
			}

			require.NotZero(t, attrs.Len())
			got := make(map[string]string)
			for _, kv := range attrs.ToSlice() {
				got[string(kv.Key)] = kv.Value.AsString()
			}
			assert.Equal(t, tt.expected, got)
		})
	}
}

// Resolve distinguishes a zero Info (never resolved, or invalidated by an exec)
// from a resolved context that happens to carry nothing.
func TestResolve(t *testing.T) {
	envVars := map[libpf.String]libpf.String{
		libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("svc"),
	}
	serviceName := func(t *testing.T, info Info) string {
		t.Helper()
		v, ok := info.ResourceAttrs.Value("service.name")
		require.True(t, ok)
		return v.AsString()
	}
	// Callers store the result unconditionally, so an unresolved Info would
	// publish empty attributes.
	resolve := func(t *testing.T, mappingAddr uint64, rm remotememory.RemoteMemory,
		old Info, envVars map[libpf.String]libpf.String,
	) Info {
		t.Helper()
		info := Resolve(mappingAddr, 1, rm, old, envVars)
		require.True(t, info.resolved)
		return info
	}
	// A resolved context carrying nothing: no mapping, no env vars.
	resolvedEmpty := resolve(t, 0, remotememory.RemoteMemory{}, Info{}, nil)
	// A header stuck mid-update, so read exhausts its retries and reports a
	// concurrent update.
	midUpdate := func() remotememory.RemoteMemory {
		mock := newMockReader()
		mock.writeAt(0x1000, createValidHeader(100, 0x2000, 0))
		return remotememory.RemoteMemory{ReaderAt: mock}
	}

	t.Run("zero Info resolves with no mapping and no env vars", func(t *testing.T) {
		info := resolve(t, 0, remotememory.RemoteMemory{}, Info{}, nil)
		assert.Zero(t, info.publishedAtNs)
	})

	t.Run("zero Info resolves from env vars", func(t *testing.T) {
		info := resolve(t, 0, remotememory.RemoteMemory{}, Info{}, envVars)
		assert.Equal(t, "svc", serviceName(t, info))
	})

	t.Run("resolved and empty is steady state", func(t *testing.T) {
		info := resolve(t, 0, remotememory.RemoteMemory{}, resolvedEmpty, envVars)
		assert.Equal(t, resolvedEmpty, info, "unchanged old must come back as-is")
	})

	t.Run("mapping disappeared clears its attributes", func(t *testing.T) {
		old := Info{
			ResourceAttrs: attribute.NewSet(attribute.String("from.mapping", "v")),
			publishedAtNs: 7,
			resolved:      true,
		}
		info := resolve(t, 0, remotememory.RemoteMemory{}, old, envVars)
		_, found := info.ResourceAttrs.Value("from.mapping")
		assert.False(t, found, "mapping attributes must not outlive the mapping")
		assert.Equal(t, "svc", serviceName(t, info))
	})

	t.Run("concurrent update preserves a resolved context", func(t *testing.T) {
		info := resolve(t, 0x1000, midUpdate(), resolvedEmpty, envVars)
		assert.Equal(t, resolvedEmpty, info, "unchanged old must come back as-is")
	})

	t.Run("concurrent update on a zero Info falls back to env vars", func(t *testing.T) {
		info := resolve(t, 0x1000, midUpdate(), Info{}, envVars)
		assert.Equal(t, "svc", serviceName(t, info))
	})

	t.Run("read failure falls back to env vars", func(t *testing.T) {
		mock := newMockReader()
		mock.setError(errors.New("read error"))
		info := resolve(t, 0x1000,
			remotememory.RemoteMemory{ReaderAt: mock}, Info{}, envVars)
		assert.Equal(t, "svc", serviceName(t, info))
	})

	t.Run("successfully read context is published as-is, env vars ignored", func(t *testing.T) {
		payload, err := proto.Marshal(&testContext)
		require.NoError(t, err)
		const payloadAddr = 0x2000
		mock := newMockReader()
		mock.writeAt(0x1000, createValidHeader(uint32(len(payload)), payloadAddr, 7))
		mock.writeAt(payloadAddr, payload)
		rm := remotememory.RemoteMemory{ReaderAt: mock}

		envVarsWithExtra := map[libpf.String]libpf.String{
			libpf.Intern("OTEL_SERVICE_NAME"):        libpf.Intern("svc"),
			libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("deployment.environment=prod"),
		}
		info := resolve(t, 0x1000, rm, Info{}, envVarsWithExtra)
		assert.Equal(t, "test-service", serviceName(t, info), "context resource.name must win")
		_, found := info.ResourceAttrs.Value("deployment.environment")
		assert.False(t, found, "env vars must not be merged into a successfully read context")
	})

	t.Run("unchanged timestamp is steady state", func(t *testing.T) {
		payload, err := proto.Marshal(&testContext)
		require.NoError(t, err)
		const payloadAddr = 0x2000
		mock := newMockReader()
		mock.writeAt(0x1000, createValidHeader(uint32(len(payload)), payloadAddr, 7))
		mock.writeAt(payloadAddr, payload)
		rm := remotememory.RemoteMemory{ReaderAt: mock}

		first := resolve(t, 0x1000, rm, Info{}, envVars)
		require.Equal(t, uint64(7), first.publishedAtNs)

		second := resolve(t, 0x1000, rm, first, envVars)
		assert.Equal(t, first, second, "same timestamp must return old unchanged")
	})
}
