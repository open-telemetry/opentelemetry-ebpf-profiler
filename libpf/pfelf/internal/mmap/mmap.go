// Package mmap is inspired by golang.org/x/exp/mmap with
// additional functionality.
package mmap // import "go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"syscall"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// ReaderAt reads a memory-mapped file.
//
// Like any io.ReaderAt, clients can execute parallel ReadAt calls, but it is
// not safe to call Close and reading methods concurrently.
type ReaderAt struct {
	data []byte
}

var _ libpf.ViewAtReader = &ReaderAt{}

// Close closes the reader.
func (r *ReaderAt) Close() error {
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

// ViewAt implements the libpf.ViewAtReader interface. The returned view
// extends up to the end of the mapping.
func (r *ReaderAt) ViewAt(offs int64, minLen int) ([]byte, error) {
	if offs < 0 {
		return nil, fmt.Errorf("mmap: negative ViewAt offset %d", offs)
	}
	if minLen <= 0 {
		minLen = 1
	}
	if offs >= int64(r.Len()) || int64(r.Len())-offs < int64(minLen) {
		return nil, io.EOF
	}
	return r.data[offs:], nil
}

// PinAt implements the libpf.ViewAtReader interface. The mapping is
// naturally stable for its full lifetime, so pinning is trivial: the view
// is valid until the mapping is closed.
func (r *ReaderAt) PinAt(offs int64, minLen int) ([]byte, libpf.PinHandle, error) {
	view, err := r.ViewAt(offs, minLen)
	return view, 0, err
}

// Unpin implements the libpf.ViewAtReader interface. It is a no-op, as
// the mapping is naturally stable.
func (r *ReaderAt) Unpin(h libpf.PinHandle) {}

var _ libpf.StableViewer = &ReaderAt{}

// StableViewAt returns a zero-copy view of length bytes starting at offs.
// The mapping is naturally stable for its full lifetime. Returns nil if
// the range is out of bounds.
func (r *ReaderAt) StableViewAt(offs int64, length int) []byte {
	if offs < 0 || length <= 0 || offs >= int64(r.Len()) ||
		int64(r.Len())-offs < int64(length) {
		return nil
	}
	return r.data[offs : offs+int64(length)]
}

// Open memory-maps the named file for reading.
func Open(filename string) (*ReaderAt, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return OpenFile(f)
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
	runtime.SetFinalizer(r, (*ReaderAt).Close)
	r.setRandom()
	return r, nil
}
