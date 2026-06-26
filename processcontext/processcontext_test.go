// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package processcontext_test

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/processcontext"
	processcontextpb "go.opentelemetry.io/ebpf-profiler/processcontext/v1development"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

const (
	headerSignature  = "OTEL_CTX"
	supportedVersion = 2
	headerSize       = 32
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
	ExtraAttributes: []*commonpb.KeyValue{
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

// mockReader implements io.ReaderAt for testing.
// It stores data as a set of (address, bytes) regions and supports reads
// that span within any single stored region.
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

func createHeader(signature string, version uint32, payloadSize uint32, payloadPtr uint64, publishedAt uint64) []byte {
	buf := make([]byte, headerSize)
	copy(buf[0:8], []byte(signature))
	binary.LittleEndian.PutUint32(buf[8:12], version)
	binary.LittleEndian.PutUint32(buf[12:16], payloadSize)
	binary.LittleEndian.PutUint64(buf[16:24], publishedAt)
	binary.LittleEndian.PutUint64(buf[24:32], payloadPtr)
	return buf
}

// createValidHeader creates a valid ProcessContext header
func createValidHeader(payloadSize uint32, payloadPtr uint64, publishedAt uint64) []byte {
	return createHeader(headerSignature, supportedVersion, payloadSize, payloadPtr, publishedAt)
}

func TestProcessContext_IsContextMapping(t *testing.T) {
	assert.True(t, processcontext.IsContextMapping(false, "[anon:OTEL_CTX]"))
	assert.True(t, processcontext.IsContextMapping(false, "[anon_shmem:OTEL_CTX]"))
	assert.True(t, processcontext.IsContextMapping(false, "/memfd:OTEL_CTX"))
	assert.True(t, processcontext.IsContextMapping(false, "/memfd:OTEL_CTX (deleted)"))
	assert.False(t, processcontext.IsContextMapping(false, "test"))
	assert.False(t, processcontext.IsContextMapping(true, "[anon:OTEL_CTX]"))
}

func TestProcessContext_Read(t *testing.T) {
	payload, err := proto.Marshal(&testContext)
	require.NoError(t, err)

	mappingAddr := libpf.Address(0x1000)

	tests := []struct {
		name              string
		setupMock         func(*mockReader)
		expectedResult    processcontext.Info
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
			expectedResult: processcontext.Info{
				Resource:        expectedResource(),
				ExtraAttributes: expectedExtraAttributes(),
				PublishedAtNs:   123456789,
			},
		},
		{
			name: "read error",
			setupMock: func(mock *mockReader) {
				mock.setError(errors.New("read error"))
			},
			expectedErr: processcontext.ErrInvalidContext,
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
			expectedErr:    processcontext.ErrInvalidContext,
			errorSubstring: "failed to unmarshal",
		},
		{
			name: "invalid signature",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader("INVALID!", supportedVersion, 100, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    processcontext.ErrInvalidContext,
			errorSubstring: "signature",
		},
		{
			name: "invalid version",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader(headerSignature, 999, 100, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    processcontext.ErrInvalidContext,
			errorSubstring: "version",
		},
		{
			name: "zero payload size",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(0, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    processcontext.ErrInvalidContext,
			errorSubstring: "payload size",
		},
		{
			name: "payload size too large",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createHeader(headerSignature, supportedVersion, 1024*1024, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    processcontext.ErrInvalidContext,
			errorSubstring: "payload size",
		},
		{
			name: "published at zero - update in progress",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				// PublishedAtNs = 0 indicates update in progress
				header := createValidHeader(100, 0x2000, 0)
				mock.writeAt(headerAddr, header)
			},
			expectedErr: processcontext.ErrConcurrentUpdate,
		},
		{
			name: "published at same as last published",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(100, 0x2000, 123456788)
				mock.writeAt(headerAddr, header)
			},
			lastPublishedAtNs: 123456788,
			expectedErr:       processcontext.ErrNoUpdate,
		},
		{
			name: "published at too old",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(mappingAddr)
				header := createValidHeader(100, 0x2000, 123456787)
				mock.writeAt(headerAddr, header)
			},
			lastPublishedAtNs: 123456788,
			expectedErr:       processcontext.ErrNoUpdate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReader()
			tt.setupMock(mock)

			rm := remotememory.RemoteMemory{ReaderAt: mock}

			ctx, err := processcontext.Read(mappingAddr, rm, tt.lastPublishedAtNs, 0)

			if tt.expectedErr == nil {
				require.NoError(t, err)
				require.NotNil(t, ctx)
				require.EqualExportedValues(t, &tt.expectedResult, &ctx)
			} else {
				assert.Nil(t, ctx.Resource)
				assert.Nil(t, ctx.ExtraAttributes)
				assert.Zero(t, ctx.PublishedAtNs)
				assert.Error(t, err)
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
			// Create test ProcessContext
			payload, err := proto.Marshal(&testContext)
			require.NoError(t, err)

			payloadAddr := libpf.Address(unsafe.Pointer(&payload[0]))
			header := createValidHeader(uint32(len(payload)), uint64(payloadAddr), 123456789)

			memSize := len(header)
			var mem []byte
			if tt.useMemfd {
				// Create memfd with OTEL_CTX name
				fd, err := unix.MemfdCreate(headerSignature, 0)
				require.NoError(t, err)
				defer unix.Close(fd)

				// Set size of memfd
				err = unix.Ftruncate(fd, int64(memSize))
				require.NoError(t, err)
				// Map the memfd into memory
				mem, err = unix.Mmap(
					fd, 0, memSize,
					unix.PROT_READ|unix.PROT_WRITE,
					unix.MAP_PRIVATE,
				)
				require.NoError(t, err)
				defer unix.Munmap(mem)
				unix.Close(fd)
			} else {
				// Create  private anonymous memory mapping
				mem, err = unix.Mmap(
					-1, 0, memSize,
					unix.PROT_READ|unix.PROT_WRITE,
					unix.MAP_PRIVATE|unix.MAP_ANONYMOUS,
				)
				require.NoError(t, err)
				defer unix.Munmap(mem)
			}

			// Write ProcessContext to memory
			copy(mem[0:len(header)], header)

			if tt.usePrctl {
				// Name the memory region using prctl
				nameNullTerminated, _ := unix.ByteSliceFromString(headerSignature)
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

			// Get current process mappings
			pid := libpf.PID(os.Getpid())
			proc := process.New(pid, pid)
			defer proc.Close()

			var contextMappingAddr uint64
			_, err = proc.IterateMappings(func(m process.RawMapping) bool {
				if processcontext.IsContextMapping(m.IsExecutable(), m.Path) {
					contextMappingAddr = m.Vaddr
					return false
				}
				return true
			})
			if err != nil && !errors.Is(err, process.ErrCallbackStopped) {
				require.NoError(t, err)
			}
			require.NotZero(t, contextMappingAddr)

			result, err := processcontext.Read(libpf.Address(contextMappingAddr), proc.GetRemoteMemory(), 0, 0)
			require.NoError(t, err)
			require.EqualExportedValues(t,
				processcontext.Info{
					Resource:        expectedResource(),
					ExtraAttributes: expectedExtraAttributes(),
					PublishedAtNs:   123456789,
				},
				result)

		})
	}
}

func expectedResource() *pcommon.Resource {
	r := pcommon.NewResource()
	r.Attributes().PutStr("service.name", "test-service")
	r.Attributes().PutInt("service.version", 42)
	r.Attributes().PutBool("service.active", true)
	r.Attributes().PutDouble("service.weight", 3.14)

	tags := r.Attributes().PutEmptySlice("service.tags")
	tags.AppendEmpty().SetStr("tag1")
	tags.AppendEmpty().SetInt(2)

	metadata := r.Attributes().PutEmptyMap("service.metadata")
	metadata.PutStr("nested.key", "nested-value")
	metadata.PutInt("nested.count", 7)

	return &r
}

func expectedExtraAttributes() *pcommon.Map {
	m := pcommon.NewMap()
	m.PutStr("custom.attribute", "custom-value")
	return &m
}

func TestWithMergedEnvVars(t *testing.T) {
	tests := []struct {
		name        string
		preexisting map[string]string
		envVars     map[libpf.String]libpf.String
		expected    map[string]string
	}{
		{
			name: "no env vars no preexisting",
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
			name: "OTEL_RESOURCE_ATTRIBUTES invalid encoding in value discards all",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,bad=%ZZ"),
			},
			// Per OTel spec, the entire value is discarded on any error.
			expected: nil,
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES invalid encoding in key discards all",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,bad%ZZ=value2"),
			},
			// Per OTel spec, the entire value is discarded on any error.
			expected: nil,
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES missing equals discards all",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("good=value,badpair"),
			},
			// Per OTel spec, the entire value is discarded on any error.
			expected: nil,
		},
		{
			name: "OTEL_RESOURCE_ATTRIBUTES empty value",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern(""),
			},
			expected: nil,
		},
		{
			name:        "OTEL_SERVICE_NAME does not override existing",
			preexisting: map[string]string{"service.name": "test-service"},
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_SERVICE_NAME"): libpf.Intern("env-service"),
			},
			expected: map[string]string{
				"service.name": "test-service",
			},
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
			// Per OTel spec, duplicate keys within OTEL_RESOURCE_ATTRIBUTES
			// resolve last-writer-wins.
			name: "OTEL_RESOURCE_ATTRIBUTES duplicate keys: last writer wins",
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("k=first,k=second,k=third"),
			},
			expected: map[string]string{
				"k": "third",
			},
		},
		{
			// Pre-existing values on p.Resource still beat OTEL_RESOURCE_ATTRIBUTES,
			// so the dedup-then-apply order is observable: even though the value
			// "from-attrs-second" wins the intra-attr dedup, "preset" wins overall.
			name:        "preexisting attribute beats OTEL_RESOURCE_ATTRIBUTES last writer",
			preexisting: map[string]string{"k": "preset"},
			envVars: map[libpf.String]libpf.String{
				libpf.Intern("OTEL_RESOURCE_ATTRIBUTES"): libpf.Intern("k=from-attrs-first,k=from-attrs-second"),
			},
			expected: map[string]string{
				"k": "preset",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := processcontext.Info{}
			if tt.preexisting != nil {
				r := pcommon.NewResource()
				for k, v := range tt.preexisting {
					r.Attributes().PutStr(k, v)
				}
				info.Resource = &r
			}

			info = processcontext.WithMergedEnvVars(info, tt.envVars)

			if tt.expected == nil {
				if tt.preexisting == nil {
					assert.Nil(t, info.Resource)
				}
				return
			}

			require.NotNil(t, info.Resource)
			got := make(map[string]string)
			info.Resource.Attributes().Range(func(k string, v pcommon.Value) bool {
				got[k] = v.Str()
				return true
			})
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestResourceToContextKey(t *testing.T) {
	tests := []struct {
		name     string
		attrs    map[string]string
		nilRes   bool
		expected string
	}{
		{
			name:     "nil resource",
			nilRes:   true,
			expected: "",
		},
		{
			name:     "empty resource",
			attrs:    nil,
			expected: "",
		},
		{
			name: "all three present",
			attrs: map[string]string{
				"service.namespace":   "ns",
				"service.name":        "svc",
				"service.instance.id": "id",
			},
			expected: "ns:svc:id",
		},
		{
			name: "missing namespace",
			attrs: map[string]string{
				"service.name":        "svc",
				"service.instance.id": "id",
			},
			expected: ":svc:id",
		},
		{
			name: "missing name",
			attrs: map[string]string{
				"service.namespace":   "ns",
				"service.instance.id": "id",
			},
			expected: "ns::id",
		},
		{
			name: "missing instance id",
			attrs: map[string]string{
				"service.namespace": "ns",
				"service.name":      "svc",
			},
			expected: "ns:svc:",
		},
		{
			name: "irrelevant attributes ignored",
			attrs: map[string]string{
				"service.namespace":   "ns",
				"service.name":        "svc",
				"service.instance.id": "id",
				"deployment.env":      "prod",
			},
			expected: "ns:svc:id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var res *pcommon.Resource
			if !tt.nilRes {
				r := pcommon.NewResource()
				for k, v := range tt.attrs {
					r.Attributes().PutStr(k, v)
				}
				res = &r
			}
			assert.Equal(t, tt.expected, processcontext.ResourceToContextKey(res).String())
		})
	}
}
