//go:build linux

// Package mmap is inspired by golang.org/x/exp/mmap with
// additional functionality.
package mmap // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
)

func closeData(data []byte) error {
	return syscall.Munmap(data)
}

// OpenFile memory-maps the OS file for reading.
func OpenFile(f *os.File) (*ReaderAt, error) {
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := fi.Size()
	if size == 0 {
		// Treat (size == 0) as a special case, avoiding the syscall, since
		// "man 2 mmap" says "the length... must be greater than 0".
		//
		// As we do not call syscall.Mmap, there is no need to call
		// runtime.SetFinalizer to enforce a balancing syscall.Munmap.
		return &ReaderAt{
			data: make([]byte, 0),
		}, nil
	}
	if size < 0 {
		return nil, fmt.Errorf("mmap: negative file size")
	}
	if size != int64(int(size)) {
		return nil, fmt.Errorf("mmap: too large file size")
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, err
	}

	r := &ReaderAt{data: data}
	r.refCount.Store(1)
	runtime.SetFinalizer(r, (*ReaderAt).Close)
	r.setRandom()
	return r, nil
}

func (r *ReaderAt) SetMadvDontNeed() error {
	return syscall.Madvise(r.data, syscall.MADV_DONTNEED)
}

func (r *ReaderAt) setRandom() error {
	return syscall.Madvise(r.data, syscall.MADV_RANDOM)
}
