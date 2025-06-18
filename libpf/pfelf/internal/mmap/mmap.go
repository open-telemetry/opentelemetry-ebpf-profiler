// Package mmap is inspired by golang.org/x/exp/mmap with
// additional functionality.
package mmap // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"unsafe"
)

var (
	// ErrInvalRequest indicates that the requested data exceeds the available mapped data.
	ErrInvalRequest = errors.New("invalid request")
)

// ReaderAt reads a memory-mapped file.
//
// Like any io.ReaderAt, clients can execute parallel ReadAt calls, but it is
// not safe to call Close and reading methods concurrently.
type ReaderAt struct {
	// refCount is the number of references
	refCount atomic.Int32

	data []byte
}

// Take takes a reference on the data
func (r *ReaderAt) Take() io.Closer {
	r.refCount.Add(1)
	return r
}

// Close closes the reader.
func (r *ReaderAt) Close() error {
	// Drop reference
	if r.refCount.Add(-1) != 0 {
		return nil
	}
	// No more references - unmap data
	if r.data == nil {
		return nil
	} else if len(r.data) == 0 {
		r.data = nil
		return nil
	}
	data := r.data
	r.data = nil
	runtime.SetFinalizer(r, nil)
	return syscall.Munmap(data)
}

// Len returns the length of the underlying memory-mapped file.
func (r *ReaderAt) Len() int {
	return len(r.data)
}

// At returns the byte at index i.
func (r *ReaderAt) At(i int) byte {
	return r.data[i]
}

// ReadAt implements the io.ReaderAt interface.
func (r *ReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if r.data == nil {
		return 0, errors.New("mmap: closed")
	}
	if off < 0 || int64(len(r.data)) < off {
		return 0, fmt.Errorf("mmap: invalid ReadAt offset %d", off)
	}
	n := copy(p, r.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Subslice returns a subset of the mmaped backed data.
func (r *ReaderAt) Subslice(offset, length int) ([]byte, error) {
	if offset+length > r.Len() {
		return nil, fmt.Errorf("requested data %d at 0x%x exceeds %d: %w",
			length, offset, length, ErrInvalRequest)
	}
	return unsafe.Slice((*byte)(unsafe.Pointer(&r.data[offset])), length), nil
}

// Open memory-maps the named file for reading.
func Open(filename string) (*ReaderAt, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
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
		return nil, fmt.Errorf("mmap: file %q has negative size", filename)
	}
	if size != int64(int(size)) {
		return nil, fmt.Errorf("mmap: file %q is too large", filename)
	}

	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), syscall.PROT_READ, syscall.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	r := &ReaderAt{data: data}
	r.refCount.Store(1)
	runtime.SetFinalizer(r, (*ReaderAt).Close)
	return r, nil
}
