// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"debug/elf"
	"testing"

	"github.com/elastic/go-perf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestMmapRecordToEvent(t *testing.T) {
	got, ok := mmapRecordToEvent(&perf.Mmap2Record{
		Pid:        123,
		Tid:        456,
		Addr:       0x1000,
		Len:        0x2000,
		PageOffset: 0x3000,
		MajorID:    8,
		MinorID:    1,
		Inode:      789,
		Prot:       unix.PROT_READ | unix.PROT_EXEC,
		Filename:   "/usr/lib/libc.so.6",
	})
	require.True(t, ok)
	require.Equal(t, libpf.PID(123), got.pid)
	require.Equal(t, libpf.PID(456), got.tid)
	require.Equal(t, uint64(0x1000), got.mapping.Vaddr)
	require.Equal(t, uint64(0x2000), got.mapping.Length)
	require.Equal(t, uint64(0x3000), got.mapping.FileOffset)
	require.Equal(t, unix.Mkdev(8, 1), got.mapping.Device)
	require.Equal(t, uint64(789), got.mapping.Inode)
	require.Equal(t, "/usr/lib/libc.so.6", got.mapping.Path)
	require.Equal(t, elf.PF_R|elf.PF_X, got.mapping.Flags)
	require.True(t, got.mapping.IsExecutable())

	_, ok = mmapRecordToEvent(&perf.Mmap2Record{Pid: 123, Tid: 456})
	require.False(t, ok, "mapping without a backing inode should be ignored")

	_, ok = mmapRecordToEvent(&perf.MmapRecord{Pid: 123, Tid: 456})
	require.False(t, ok, "legacy MMAP record should be ignored")

	_, ok = mmapRecordToEvent(&perf.LostRecord{})
	require.False(t, ok)
}
