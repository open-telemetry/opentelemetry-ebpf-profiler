// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package remotememory

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func RemoteMemTests(t *testing.T, rm RemoteMemory) {
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
	assert.Equal(t, uint32(0x04030201), rm.Uint32(dataPtr))
	assert.Equal(t, libpf.Address(0x0807060504030201), rm.Ptr(dataPtr))
	assert.Equal(t, string(str[:len(str)-1]), rm.String(strPtr))
	assert.Equal(t, string(longStr[:len(longStr)-1]), rm.String(longStrPtr))
}

func TestProcessVirtualMemoryPaths(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("unsupported os %s", runtime.GOOS)
	}

	pid := os.Getpid()

	// Symlink /proc/<pid>/mem into a temp dir so the procfs code path reads
	// the same process memory as the syscall path, letting us compare results.
	tmpDir := t.TempDir()
	procDir := filepath.Join(tmpDir, "proc", strconv.Itoa(pid))
	require.NoError(t, os.MkdirAll(procDir, 0o755))
	require.NoError(t, os.Symlink(
		fmt.Sprintf("/proc/%d/mem", pid),
		filepath.Join(procDir, "mem"),
	))

	tests := []struct {
		name       string
		rootFsPath string
	}{
		{"host_syscall", "/"},
		{"custom_procfs", tmpDir},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rm, err := NewProcessVirtualMemory(libpf.PID(pid), tc.rootFsPath)
			require.NoError(t, err)
			RemoteMemTests(t, rm)
		})
	}
}
