// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package pfbufio provides caching reader implementation similar to bufio,
// but with additional primitives and being more GC friendly.
package pfbufio // import "go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"

import (
	"bytes"
	"errors"
	"io"
	"math"
	"sync"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
)

// ErrBufferTooSmall is returned if trying the request cannot be satisfied
// due to too small buffer.
var ErrBufferTooSmall = errors.New("buffer too small")

// bufferSize is a build-time constant for the internal array.
const bufferSize = 64 * 1024

// Reader implements a pooled, buffered io.Reader on top of io.ReaderAt.
type Reader struct {
	source io.ReaderAt

	start int64 // Original start offset
	off   int64 // Source offset where the next ReadAt will start
	limit int64 // Maximum source offset allowed

	pos  int // Current read position in buf
	size int // Valid data currently in buf

	buf [bufferSize]byte
}

var readerPool = sync.Pool{
	New: func() any {
		return &Reader{}
	},
}

// GetReader fetches a Reader from the pool.
func GetReader() *Reader {
	r := readerPool.Get().(*Reader)
	return r
}

// NewReader fetches a Reader from the pool and initializes it.
func NewReader(source io.ReaderAt, start, maxLen int64) *Reader {
	r := GetReader()
	r.Init(source, start, maxLen)
	return r
}

// PutReader clears references and returns the Reader to the pool.
func PutReader(r *Reader) {
	r.source = nil
	r.off = 0
	r.limit = 0
	r.pos = 0
	r.size = 0
	readerPool.Put(r)
}

// Init initializes the reader source.
func (r *Reader) Init(source io.ReaderAt, start, maxLen int64) {
	r.source = source
	r.start = start
	r.off = start
	r.limit = start + maxLen
	r.pos = 0
	r.size = 0
}

// Tell returns the current position in the stream relative to the 'start'.
func (r *Reader) Tell() int64 {
	return r.off - r.start - int64(r.size-r.pos)
}

// fill populates the internal array from the source.
func (r *Reader) fill() error {
	if r.off >= r.limit {
		return io.EOF
	}

	// Move unconsumed bytes to the start of the buffer
	preserve := r.size - r.pos
	if preserve > 0 && r.pos > 0 {
		copy(r.buf[:preserve], r.buf[r.pos:r.pos+preserve])
	}

	r.pos = 0
	toRead := int64(bufferSize - preserve)
	if toRead > r.limit-r.off {
		toRead = r.limit - r.off
	}

	n, err := r.source.ReadAt(r.buf[preserve:preserve+int(toRead)], r.off)
	r.size = n + preserve
	r.off += int64(n)

	if n > 0 {
		return nil
	}
	if err == nil {
		return io.EOF
	}
	return err
}

// Read implements io.Reader.
func (r *Reader) Read(p []byte) (n int, err error) {
	// Loop until p is full or we hit an error/EOF
	for n < len(p) {
		// 1. If buffer has data, copy it out.
		if r.pos < r.size {
			copied := copy(p[n:], r.buf[r.pos:r.size])
			r.pos += copied
			n += copied
			continue
		}

		// 2. Buffer is empty. Check if we've reached the limit.
		if r.off >= r.limit {
			if n > 0 {
				// Return what we have, next call will hit EOF
				return n, nil
			}
			return 0, io.EOF
		}

		// 3. Read directly to target buffer if there's lot of data to read.
		toRead := int64(len(p) - n)
		if toRead >= bufferSize {
			if toRead > r.limit-r.off {
				toRead = r.limit - r.off
			}
			fn, ferr := r.source.ReadAt(p[n:n+int(toRead)], r.off)
			r.off += int64(fn)
			n += fn
			return n, ferr
		}

		// 4. Small read remaining: Fill internal buffer and loop again.
		if err := r.fill(); err != nil {
			if n == len(p) {
				err = nil
			}
			return n, err
		}
	}
	return n, nil
}

// ReadByte reads and returns a single byte.
func (r *Reader) ReadByte() (byte, error) {
	if r.pos >= r.size {
		if err := r.fill(); err != nil {
			return 0, err
		}
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

// Discard skips the next n bytes.
func (r *Reader) Discard(n int) (discarded int, err error) {
	if n < 0 {
		return 0, errors.New("negative discard count")
	}
	for discarded < n {
		if r.pos >= r.size {
			if err = r.fill(); err != nil {
				return discarded, err
			}
		}
		partial := min(r.size-r.pos, n-discarded)
		r.pos += partial
		discarded += partial
	}
	return discarded, nil
}

// Peek returns the internal buffer for next 'n' bytes if possible.
// The returned slice points to the internal buffer and is invalid after the next read.
func (r *Reader) Peek(n int) ([]byte, error) {
	if n > bufferSize {
		return nil, ErrBufferTooSmall
	}
	if r.size-r.pos < n {
		if err := r.fill(); err != nil {
			return nil, err
		}
	}
	if r.size-r.pos >= n {
		b := r.buf[r.pos : r.pos+n]
		return b, nil
	}
	return nil, io.EOF
}

// ReadN reads and returns a byte slice to 'n' bytes of data.
// The returned slice points to the internal buffer and is invalid after the next read.
func (r *Reader) ReadN(n int) ([]byte, error) {
	b, err := r.Peek(n)
	if b != nil {
		r.pos += n
	}
	return b, err
}

// ReadStringN reads a string with a length of 'n' bytes.
// The returned string points to the internal buffer and is invalid after the next read.
func (r *Reader) ReadStringN(n int) (string, error) {
	slice, err := r.ReadN(n)
	return pfunsafe.ToString(slice), err
}

// ReadSlice reads until the first occurrence of delim.
// The returned slice points to the internal buffer and is invalid after the next read.
func (r *Reader) ReadSlice(delim byte) ([]byte, error) {
	for {
		if i := bytes.IndexByte(r.buf[r.pos:r.size], delim); i >= 0 {
			res := r.buf[r.pos : r.pos+i]
			r.pos += i + 1
			return res, nil
		}

		if r.off >= r.limit {
			res := r.buf[r.pos:r.size]
			r.pos = r.size
			return res, io.EOF
		}

		// If buffer is full and no delim, we must clear it to find the delim
		if r.pos == 0 && r.size == bufferSize {
			r.pos = r.size
			return r.buf[:], ErrBufferTooSmall
		}

		if err := r.fill(); err != nil {
			return nil, err
		}
	}
}

// ReadString reads until the first occurrence of delim and returns a string.
// The returned string points to the internal buffer and is invalid after the next read.
func (r *Reader) ReadString(delim byte) (string, error) {
	slice, err := r.ReadSlice(delim)
	return pfunsafe.ToString(slice), err
}

// WalkStrings reads up to 'n' strings and calls the callback for each string
// with its offset from the original reader start.
// The string points to the internal buffer and is invalid after callback returns.
func (r *Reader) WalkStrings(n int, fn func(offset int64, s string) error) error {
	for i := n; i > 0; i-- {
		offset := r.Tell()
		s, err := r.ReadString(0)
		if err != nil {
			return err
		}
		if err = fn(offset, s); err != nil {
			return err
		}
	}
	return nil
}

// WalkAllStrings is similar to WalkStrings, but walks all strings until EOF.
func (r *Reader) WalkAllStrings(fn func(offset int64, s string) error) error {
	if err := r.WalkStrings(math.MaxInt, fn); err != io.EOF {
		return err
	}
	return nil
}

// SearchSlice moves the reader position to immediately AFTER the pattern.
// Returns the absolute offset of the START of the pattern.
func (r *Reader) SearchSlice(pattern []byte) (int64, error) {
	plen := len(pattern)
	if plen == 0 {
		return r.Tell(), nil
	}

	for {
		// Index in current buffer view
		i := bytes.Index(r.buf[r.pos:r.size], pattern)
		if i >= 0 {
			matchStart := r.Tell() + int64(i)
			r.pos += i + plen // Advance cursor to AFTER the pattern
			return matchStart, nil
		}

		// Pattern not found; discard unmatched data, but keep up to (plen-1)
		// bytes to catch patterns split across buffer boundaries.
		r.pos = r.size - min(r.size-r.pos, plen-1)
		if err := r.fill(); err != nil {
			r.pos = r.size
			return -1, err
		}
	}
}
