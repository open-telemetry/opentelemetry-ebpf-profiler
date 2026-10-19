//go:build linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package apmint

import (
	"encoding/binary"
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestReadProcStorage_ZeroPointer(t *testing.T) {
	// A memory buffer containing a NULL pointer (0x0)
	var ptrBuf [8]byte
	rm := remotememory.NewProcessVirtualMemory(libpf.PID(os.Getpid()))

	procStorageAddr := libpf.Address(uintptr(unsafe.Pointer(&ptrBuf[0])))
	storage, err := readProcStorage(rm, procStorageAddr, libpf.PID(os.Getpid()))

	assert.Nil(t, storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read Java agent process state pointer")
}

func TestReadProcStorage_UnsafePointer(t *testing.T) {
	// A memory buffer containing an invalid / unmapped address
	var ptrBuf [8]byte
	binary.LittleEndian.PutUint64(ptrBuf[:], 0xdeadbeef0000)

	rm := remotememory.NewProcessVirtualMemory(libpf.PID(os.Getpid()))
	procStorageAddr := libpf.Address(uintptr(unsafe.Pointer(&ptrBuf[0])))

	storage, err := readProcStorage(rm, procStorageAddr, libpf.PID(os.Getpid()))

	// Must fail at the validation step before attempting any memory reads
	assert.Nil(t, storage)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsafe APM process storage pointer")
}

func TestReadProcStorage_ValidAnonymous(t *testing.T) {
	// Construct a valid APM storage buffer on the heap (anonymous memory)
	storageBuf := make([]byte, maxProcStorageSize)
	offset := 0

	// 1. layout_minor_version (uint16 = 1)
	binary.LittleEndian.PutUint16(storageBuf[offset:], 1)
	offset += 2

	// 2. serviceName: "test-service"
	serviceName := "test-service"
	binary.LittleEndian.PutUint32(storageBuf[offset:], uint32(len(serviceName)))
	offset += 4
	copy(storageBuf[offset:], serviceName)
	offset += len(serviceName)

	// 3. serviceEnv: "test-env"
	serviceEnv := "test-env"
	binary.LittleEndian.PutUint32(storageBuf[offset:], uint32(len(serviceEnv)))
	offset += 4
	copy(storageBuf[offset:], serviceEnv)
	offset += len(serviceEnv)

	// 4. socketPath: "/tmp/apm.sock"
	socketPath := "/tmp/apm.sock"
	binary.LittleEndian.PutUint32(storageBuf[offset:], uint32(len(socketPath)))
	offset += 4
	copy(storageBuf[offset:], socketPath)

	// Create pointer referencing this anonymous storage buffer
	storageAddr := uint64(uintptr(unsafe.Pointer(&storageBuf[0])))
	var ptrBuf [8]byte
	binary.LittleEndian.PutUint64(ptrBuf[:], storageAddr)

	procStorageAddr := libpf.Address(uintptr(unsafe.Pointer(&ptrBuf[0])))
	rm := remotememory.NewProcessVirtualMemory(libpf.PID(os.Getpid()))

	storage, err := readProcStorage(rm, procStorageAddr, libpf.PID(os.Getpid()))
	require.NoError(t, err)
	require.NotNil(t, storage)

	assert.Equal(t, "test-service", storage.ServiceName)
	assert.Equal(t, "/tmp/apm.sock", storage.TraceSocketPath)
}
