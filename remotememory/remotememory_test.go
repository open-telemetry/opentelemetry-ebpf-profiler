// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package remotememory

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func RemoteMemTests(t *testing.T, rm RemoteMemory) {
	t.Helper()
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	dataPtr := libpf.Address(unsafe.Pointer(&data[0]))
	str := []byte("this is a string\x00")
	strPtr := libpf.Address(unsafe.Pointer(&str[0]))
	longStr := append(bytes.Repeat([]byte("long test string"), 4095/16), 0x00)
	longStrPtr := libpf.Address(unsafe.Pointer(&longStr[0]))

	foo := make([]byte, len(data))
	err := rm.Read(libpf.Address(unsafe.Pointer(&data)), foo)
	if errors.Is(err, syscall.ENOSYS) {
		t.Skipf("skipping due to error: %v", err)
	}
	require.NoError(t, err)
	assert.Equal(t, uint8(0x01), rm.Uint8(dataPtr))
	assert.Equal(t, uint16(0x0201), rm.Uint16(dataPtr))
	assert.Equal(t, uint32(0x04030201), rm.Uint32(dataPtr))
	assert.Equal(t, libpf.Address(0x0807060504030201), rm.Ptr(dataPtr))
	assert.Equal(t, string(str[:len(str)-1]), rm.String(strPtr))
	assert.Equal(t, string(longStr[:len(longStr)-1]), rm.String(longStrPtr))
}

func TestProcessVirtualMemory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("unsupported os %s", runtime.GOOS)
	}
	RemoteMemTests(t, NewProcessVirtualMemory(libpf.PID(os.Getpid())))
}

type errReader struct{ err error }

func (r errReader) ReadAt([]byte, int64) (int, error) { return 0, r.err }

func TestReadPtrBias(t *testing.T) {
	rm := RemoteMemory{
		ReaderAt: bytes.NewReader([]byte{0x10, 0, 0, 0, 0, 0, 0, 0}),
		Bias:     0x4,
	}

	v, err := rm.ReadPtr(0)
	require.NoError(t, err)
	assert.Equal(t, libpf.Address(0xc), v)
}

func TestReadUint64Error(t *testing.T) {
	rm := RemoteMemory{ReaderAt: errReader{err: syscall.ESRCH}}

	_, err := rm.ReadUint64(0x1000)
	require.ErrorIs(t, err, syscall.ESRCH)
	assert.Zero(t, rm.Uint64(0x1000))
}
