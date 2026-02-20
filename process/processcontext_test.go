// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package process

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
	processcontext "go.opentelemetry.io/ebpf-profiler/proto/processcontext"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
	otlpcommon "go.opentelemetry.io/proto/slim/otlp/common/v1"
	otlpresource "go.opentelemetry.io/proto/slim/otlp/resource/v1"
)

const headerSize = 32

var testProcessContext = processcontext.ProcessContext{
	Resource: &otlpresource.Resource{
		Attributes: []*otlpcommon.KeyValue{
			{
				Key: "service.name",
				Value: &otlpcommon.AnyValue{
					Value: &otlpcommon.AnyValue_StringValue{
						StringValue: "test-service",
					},
				},
			},
		},
	},
	ExtraAttributes: []*otlpcommon.KeyValue{
		{
			Key: "custom.attribute",
			Value: &otlpcommon.AnyValue{
				Value: &otlpcommon.AnyValue_StringValue{
					StringValue: "custom-value",
				},
			},
		},
	},
}

// mockReader implements io.ReaderAt for testing
type mockReader struct {
	data map[uint64][]byte
	err  error
}

func newMockReader() *mockReader {
	return &mockReader{
		data: make(map[uint64][]byte),
	}
}

func (m *mockReader) setError(err error) {
	m.err = err
}

func (m *mockReader) writeAt(addr uint64, data []byte) {
	m.data[addr] = append([]byte{}, data...)
}

func (m *mockReader) ReadAt(p []byte, off int64) (n int, err error) {
	if m.err != nil {
		return 0, m.err
	}

	addr := uint64(off)
	data, exists := m.data[addr]
	if !exists {
		return 0, io.EOF
	}

	n = copy(p, data)
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
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
	return createHeader(signatureOTELCTX, supportedVersion, payloadSize, payloadPtr, publishedAt)
}

func TestProcessContext_IsProcessContextMapping(t *testing.T) {
	assert.True(t, IsProcessContextMapping(&Mapping{Path: libpf.Intern("[anon:OTEL_CTX]")}))
	assert.True(t, IsProcessContextMapping(&Mapping{Path: libpf.Intern("/memfd:OTEL_CTX")}))
	assert.False(t, IsProcessContextMapping(&Mapping{Path: libpf.Intern("test")}))
}

func TestProcessContext_Read(t *testing.T) {
	payload, err := proto.Marshal(&testProcessContext)
	require.NoError(t, err)

	tests := []struct {
		name              string
		setupMock         func(*mockReader)
		expectedResult    ProcessContextInfo
		expectedErr       error
		errorSubstring    string
		lastPublishedAtNs uint64
	}{
		{
			name: "success with valid context",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				payloadAddr := uint64(0x2000)
				header := createValidHeader(uint32(len(payload)), payloadAddr, 123456789)
				mock.writeAt(headerAddr, header)
				mock.writeAt(payloadAddr, payload)
			},
			expectedResult: ProcessContextInfo{Context: &testProcessContext, PublishedAtNs: 123456789},
		},
		{
			name: "success with memfd mapping",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				payloadAddr := uint64(0x2000)
				header := createValidHeader(uint32(len(payload)), payloadAddr, 123456789)
				mock.writeAt(headerAddr, header)
				mock.writeAt(payloadAddr, payload)
			},
			expectedResult: ProcessContextInfo{Context: &testProcessContext, PublishedAtNs: 123456789},
		},
		{
			name: "read error",
			setupMock: func(mock *mockReader) {
				mock.setError(errors.New("read error"))
			},
			expectedErr:    ErrInvalidContext,
			errorSubstring: "failed to read ProcessContext header",
		},
		{
			name: "invalid protobuf",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				payloadAddr := uint64(0x2000)
				invalidPayload := []byte{0xff, 0xff, 0xff, 0xff}
				header := createValidHeader(uint32(len(invalidPayload)), payloadAddr, 123456789)
				mock.writeAt(headerAddr, header)
				mock.writeAt(payloadAddr, invalidPayload)
			},
			expectedErr:    ErrInvalidContext,
			errorSubstring: "failed to unmarshal",
		},
		{
			name: "invalid signature",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				header := createHeader("INVALID!", supportedVersion, 100, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    ErrInvalidContext,
			errorSubstring: "signature",
		},
		{
			name: "invalid version",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				header := createHeader(signatureOTELCTX, 999, 100, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    ErrInvalidContext,
			errorSubstring: "version",
		},
		{
			name: "zero payload size",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				header := createHeader(signatureOTELCTX, supportedVersion, 0, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    ErrInvalidContext,
			errorSubstring: "payload size",
		},
		{
			name: "payload size too large",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				header := createHeader(signatureOTELCTX, supportedVersion, maxPayloadSize+1, 0x2000, 123456789)
				mock.writeAt(headerAddr, header)
			},
			expectedErr:    ErrInvalidContext,
			errorSubstring: "payload size",
		},
		{
			name: "published at zero - update in progress",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				// PublishedAtNs = 0 indicates update in progress
				header := createValidHeader(100, 0x2000, 0)
				mock.writeAt(headerAddr, header)
			},
			expectedErr: ErrConcurrentUpdate,
		},
		{
			name: "published at too old",
			setupMock: func(mock *mockReader) {
				headerAddr := uint64(0x1000)
				header := createValidHeader(100, 0x2000, 123456788)
				mock.writeAt(headerAddr, header)
			},
			lastPublishedAtNs: 123456788,
			expectedErr:       ErrNoUpdate,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockReader()
			tt.setupMock(mock)

			rm := remotememory.RemoteMemory{ReaderAt: mock}

			mapping := &Mapping{
				Vaddr: 0x1000,
				Path:  libpf.Intern("[anon:OTEL_CTX]"),
			}

			ctx, err := ReadProcessContext(mapping, rm, tt.lastPublishedAtNs)

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

// Integration tests that create real ProcessContext memory regions

// writeProcessContextToMemory writes a ProcessContext header and payload to a memory region
func writeProcessContextToMemory(mem []byte, payload []byte) error {
	// Allocate memory for payload (after header)
	if len(mem) < headerSize+len(payload) {
		return errors.New("memory region too small")
	}

	// Write header
	headerAddr := uintptr(unsafe.Pointer(&mem[0]))
	payloadAddr := headerAddr + headerSize

	header := createHeader(signatureOTELCTX, supportedVersion,
		uint32(len(payload)), uint64(payloadAddr), 123456789)

	copy(mem[0:headerSize], header)
	copy(mem[headerSize:], payload)

	return nil
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
			payload, err := proto.Marshal(&testProcessContext)
			require.NoError(t, err)

			memSize := headerSize + len(payload)
			var mem []byte
			if tt.useMemfd {
				// Create memfd with OTEL_CTX name
				fd, err := unix.MemfdCreate("OTEL_CTX", 0)
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
			err = writeProcessContextToMemory(mem, payload)
			require.NoError(t, err)

			if tt.usePrctl {
				// Name the memory region using prctl
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

			// Get current process mappings
			pid := libpf.PID(os.Getpid())
			proc := New(pid, pid)
			defer proc.Close()

			mappings, _, err := proc.GetMappings()
			require.NoError(t, err)

			m := findContextMapping(mappings)
			require.NotNil(t, m)

			result, err := ReadProcessContext(m, proc.GetRemoteMemory(), 0)
			require.NoError(t, err)
			require.EqualExportedValues(t,
				ProcessContextInfo{Context: &testProcessContext, PublishedAtNs: 123456789},
				result)

		})
	}
}
