//go:build linux

// Package mmap is inspired by golang.org/x/exp/mmap with
// additional functionality.
package mmap // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"

import "syscall"

func setMadvDontNeed(data []byte) error {
	return syscall.Madvise(data, syscall.MADV_DONTNEED)
}
