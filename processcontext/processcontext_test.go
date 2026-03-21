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
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/processcontext"
	processcontextpb "go.opentelemetry.io/ebpf-profiler/proto/processcontext"
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
	assert.True(t, processcontext.IsContextMapping("[anon:OTEL_CTX]"))
	assert.True(t, processcontext.IsContextMapping("[anon_shmem:OTEL_CTX]"))
	assert.True(t, processcontext.IsContextMapping("/memfd:OTEL_CTX"))
	assert.False(t, processcontext.IsContextMapping("test"))
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
			expectedResult: processcontext.Info{Context: &testContext, PublishedAtNs: 123456789},
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

			ctx, err := processcontext.Read(mappingAddr, rm, tt.lastPublishedAtNs)

			if tt.expectedErr == nil {
				require.NoError(t, err)
				require.NotNil(t, ctx)
				require.EqualExportedValues(t, &tt.expectedResult, &ctx)
			} else {
				assert.Nil(t, ctx.Context)
				assert.Zero(t, ctx.PublishedAtNs)
				assert.Error(t, err)
				if tt.expectedErr != nil {
					assert.ErrorIs(t, err, tt.expectedErr)
				}
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

			mappings, _, err := proc.GetMappings()
			require.NoError(t, err)

			m := findContextMapping(mappings)
			require.NotNil(t, m)

			result, err := processcontext.Read(libpf.Address(m.Vaddr), proc.GetRemoteMemory(), 0)
			require.NoError(t, err)
			require.EqualExportedValues(t,
				processcontext.Info{Context: &testContext, PublishedAtNs: 123456789},
				result)

		})
	}
}

// findContextMapping searches for the ProcessContext memory mapping.
func findContextMapping(mappings []process.Mapping) *process.Mapping {
	for i := range mappings {
		m := &mappings[i]
		if processcontext.IsContextMapping(m.Path.String()) {
			return m
		}
	}
	return nil
}
