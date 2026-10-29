// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package pfbufio provides caching reader implementation similar to bufio,
// but with additional primitives and being more GC friendly.
package pfbufio // import "go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"math"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
)

// ErrBufferTooSmall is returned if trying the request cannot be satisfied
// due to too small buffer.
var ErrBufferTooSmall = errors.New("buffer too small")

// maxBufferSize is a build-time constant for the internal buffer size.
const maxBufferSize = 64 * 1024

// Reader implements a pooled, buffered io.Reader on top of io.ReaderAt.
// After Init()/InitFromView()/InitSlideView() the Reader must not be copied.
type Reader struct {
	source io.ReaderAt

	start  int64 // Original start offset
	off    int64 // Source offset where the next ReadAt will start
	limit  int64 // Maximum source offset allowed
	slimit int64 // Current section limit

	pos       int   // Current read position in buf
	nbuf      int   // Valid data currently in buf
	nlim      int   // Valid data in buf before sub-section limit
	bufSize   int   // Configured read-ahead buffer size
	zeroCopy  bool  // buf is a borrowed view, not owned by the Reader
	slideView bool  // fill() borrows zero-copy views from a libpf.ViewAtReader
	pinnedAt  int64 // Source offset of the pinned borrowed view, -1 if none

	sectionEnds []int64

	buf []byte
}

// NewReader returns a new reader using given source within the start
// and maxLen bounds.
func NewReader(source io.ReaderAt, start, maxLen int64) Reader {
	r := Reader{}
	r.Init(source, start, maxLen)
	return r
}

// Release clears references and returns the buffer to the pool.
func (r *Reader) Release() {
	r.dropBuf()
	r.source = nil
	r.off = 0
	r.limit = 0
	r.slimit = 0
	r.slideView = false
	r.sectionEnds = r.sectionEnds[:0]
	r.flush()
}

// dropBuf forgets the current buffer. Owned buffers are returned to the
// pool, borrowed zero-copy views are just released, and explicit pins of
// borrowed views are removed.
func (r *Reader) dropBuf() {
	if r.buf != nil && !r.zeroCopy {
		libpf.PutBuffer(r.buf)
	}
	if r.pinnedAt >= 0 && r.source != nil {
		if p, ok := r.source.(libpf.ViewAtReader); ok {
			p.UnpinAt(r.pinnedAt)
		}
	}
	r.pinnedAt = -1
	r.buf = nil
	r.zeroCopy = false
}

func (r *Reader) flush() {
	r.pos = 0
	r.nbuf = 0
	r.nlim = 0
}

// Init initializes the reader source. An initialized Reader must not
// be duplicated: both the shared buffer and the source reader position
// would get corrupted.
func (r *Reader) Init(source io.ReaderAt, start, maxLen int64) {
	r.dropBuf()
	r.init(source, start, maxLen)
	if r.buf == nil {
		r.buf = libpf.GetBuffer(maxBufferSize)
	}
	r.flush()
}

// InitFromView initializes the reader like Init, but if the source
// implements libpf.ViewAtReader and the whole area is available in one
// contiguous region, the Reader borrows a zero-copy view of the area from
// the source instead of copying the data into its own buffer.
//
// Handed-out slices of a borrowed view are invalidated not only by the
// next read on the Reader, but also by any read operation on the source
// that could evict the backing region.
func (r *Reader) InitFromView(source io.ReaderAt, start, maxLen int64) {
	r.dropBuf()
	r.init(source, start, maxLen)

	if maxLen > 0 {
		var view []byte
		var err error
		var pinned bool
		if v, ok := source.(libpf.ViewAtReader); ok {
			view, err = v.PinAt(start, maxLen)
			pinned = err == nil
		}
		if err == nil && view != nil {
			r.zeroCopy = true
			r.buf = view[:maxLen]
			r.pos = 0
			r.nbuf = int(maxLen)
			r.nlim = int(maxLen)
			r.off = start + maxLen
			if pinned {
				r.pinnedAt = start
			}
			return
		}
	}
	if r.buf == nil {
		r.buf = libpf.GetBuffer(maxBufferSize)
	}
	r.flush()
}

// InitSlideView initializes the reader like InitFromView, but if the whole
// area is not available in one contiguous region, fill() slides a zero-copy
// window over the source with libpf.ViewAtReader.ViewAt, instead of copying
// the data into its own buffer. This serves sequential readers on top of a
// page cache without double buffering.
func (r *Reader) InitSlideView(source io.ReaderAt, start, maxLen int64) {
	r.InitFromView(source, start, maxLen)
	if _, ok := source.(libpf.ViewAtReader); ok {
		r.slideView = true
	}
}

// SubReader returns a new Reader over the same source with the same area
// bounds, positioned at offset relative to the start. While the sub-reader
// is active, the parent must not be used, and the parent must remain valid
// until the sub-reader is released.
//
// If the parent holds a fully loaded zero-copy view, the sub-reader borrows
// a sub-view of it: no I/O is performed, and the view is read-only. In all
// other cases the sub-reader gets its own buffer and reads through the
// source. The current implementation never invalidates the parent on
// Release: the parent stays usable after the sub-reader is released.
func (r *Reader) SubReader(offset int64) (*Reader, error) {
	if offset < 0 || offset > r.limit-r.start {
		return nil, errOffset
	}
	sub := &Reader{}
	abs := r.start + offset
	if r.zeroCopy && r.off == r.limit && abs >= r.off-int64(r.nbuf) {
		// The parent's view fully covers [abs, limit): lend a read-only
		// sub-view of it.
		sub.zeroCopy = true
		sub.source = r.source
		sub.pinnedAt = -1
		sub.buf = r.buf[abs-(r.off-int64(r.nbuf)):]
		sub.start = r.start
		sub.limit = r.limit
		sub.slimit = r.limit
		sub.off = r.limit
		sub.nbuf = int(r.limit - abs)
		sub.nlim = sub.nbuf
		sub.bufSize = r.bufSize
		return sub, nil
	}
	// Serve from the source with an own buffer. Sliding is deliberately
	// not inherited: the sub-reader must not move the source's view pin
	// while the parent holds a view.
	sub.init(r.source, r.start, r.limit-r.start)
	sub.off = abs
	sub.bufSize = r.bufSize
	if sub.buf == nil {
		sub.buf = libpf.GetBuffer(maxBufferSize)
	}
	return sub, nil
}

// init sets the reader source and area bounds.
func (r *Reader) init(source io.ReaderAt, start, maxLen int64) {
	r.source = source
	r.start = start
	r.off = start
	r.limit = start + maxLen
	r.slimit = r.limit
	r.bufSize = maxBufferSize
	r.pinnedAt = -1
}

// SetBufferSize configures the read-ahead buffer size.
func (r *Reader) SetBufferSize(size int) {
	r.bufSize = min(max(size, 1024), maxBufferSize)
}

// Outer returns the initialization time ReaderAt and segment limits.
func (r *Reader) Outer() (source io.ReaderAt, start, maxLen int64) {
	return r.source, r.start, r.limit - r.start
}

// Remaining returns number of bytes left before end of segment or section.
func (r *Reader) Remaining() int64 {
	return r.slimit - r.off + int64(r.nbuf-r.pos)
}

var errNegativeCount = errors.New("negative count")
var errWhence = errors.New("Seek: invalid whence")
var errOffset = errors.New("Seek: invalid offset")

// Seek adjusts the current position in the stream.
func (r *Reader) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	default:
		return 0, errWhence
	case io.SeekStart:
		offset += r.start
	}
	if offset < r.start {
		return 0, errOffset
	}
	if r.zeroCopy {
		// The borrowed view must never be written to, as it may alias the
		// internal storage of the source. If the target is within the
		// loaded view, just adjust the position. Otherwise drop the window
		// contents and let the next fill() serve the new position.
		viewStart := r.off - int64(r.nbuf)
		if offset >= viewStart && offset <= r.off {
			r.pos = int(offset - viewStart)
			return offset - r.start, nil
		}
		r.off = offset
		r.flush()
		return offset - r.start, nil
	}
	r.off = offset
	r.flush()
	return offset - r.start, nil
}

// Tell returns the current position in the stream relative to the 'start'.
func (r *Reader) Tell() int64 {
	return r.off - r.start - int64(r.nbuf-r.pos)
}

// updateBufferLimit updates the 'nlim' field after 'nbuf', 'off' or 'slimit' change.
func (r *Reader) updateBufferLimit() {
	r.nlim = r.nbuf - int(max(0, r.off-r.slimit))
}

// fill populates the internal array from the source.
func (r *Reader) fill() error {
	if r.off >= r.slimit {
		return io.EOF
	}
	if r.nbuf != r.nlim {
		return io.EOF
	}

	preserve := r.nbuf - r.pos

	// Slide the zero-copy window forward if the whole area is not already
	// loaded in a borrowed view.
	if preserve == 0 && r.slideView {
		var view []byte
		var err error
		var pinned bool
		if v, ok := r.source.(libpf.ViewAtReader); ok {
			view, err = v.PinAt(r.off, 1)
			pinned = err == nil
		}
		if err == nil && view != nil {
			r.dropBuf()
			r.zeroCopy = true
			r.buf = view
			r.pos = 0
			r.nbuf = len(view)
			r.off += int64(len(view))
			r.updateBufferLimit()
			if pinned {
				r.pinnedAt = r.off - int64(len(view))
			}
			return nil
		}
	}

	if r.zeroCopy {
		// The borrowed view must never be written to: move any unconsumed
		// bytes into an owned buffer, and continue from there.
		owned := libpf.GetBuffer(maxBufferSize)
		copy(owned[:preserve], r.buf[r.pos:r.nbuf])
		r.buf = owned
		r.zeroCopy = false
		r.pos = 0
	}

	// Move unconsumed bytes to the start of the buffer
	if preserve > 0 && r.pos > 0 {
		copy(r.buf[:preserve], r.buf[r.pos:r.pos+preserve])
	}

	r.pos = 0
	toRead := min(int64(r.bufSize-preserve), r.limit-r.off)

	n, err := r.source.ReadAt(r.buf[preserve:preserve+int(toRead)], r.off)
	r.nbuf = n + preserve
	r.off += int64(n)
	r.updateBufferLimit()

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
		if r.pos < r.nlim {
			copied := copy(p[n:], r.buf[r.pos:r.nlim])
			r.pos += copied
			n += copied
			continue
		}

		// 2. Buffer is empty. Check if we've reached the limit.
		if r.nlim != r.nbuf || r.off >= r.limit {
			if n > 0 {
				// Return what we have, next call will hit EOF
				return n, nil
			}
			return 0, io.EOF
		}

		// 3. Read directly to target buffer if there's lot of data to read.
		toRead := int64(len(p) - n)
		if toRead >= int64(r.bufSize) {
			if toRead > r.slimit-r.off {
				toRead = r.slimit - r.off
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
	if r.pos >= r.nlim {
		if err := r.fill(); err != nil {
			return 0, err
		}
	}
	b := r.buf[r.pos]
	r.pos++
	return b, nil
}

// Uint8 reads an unsigned 8-bit number.
func (r *Reader) Uint8() uint8 {
	val, _ := r.ReadByte()
	return val
}

// Uint16 reads an unsigned 16-bit little-endian number.
func (r *Reader) Uint16() uint16 {
	buf, err := r.ReadN(2)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint16(buf)
}

// Uint32 reads an unsigned 32-bit little-endian number.
func (r *Reader) Uint32() uint32 {
	buf, err := r.ReadN(4)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint32(buf)
}

// Uint64 reads an unsigned 64-bit little-endian number.
func (r *Reader) Uint64() uint64 {
	buf, err := r.ReadN(8)
	if err != nil {
		return 0
	}
	return binary.LittleEndian.Uint64(buf)
}

// Int16 reads a signed 16-bit little-endian number.
func (r *Reader) Int16() int16 {
	return int16(r.Uint16())
}

// Int32 reads a signed 32-bit little-endian number.
func (r *Reader) Int32() int32 {
	return int32(r.Uint32())
}

// Int64 reads a signed 64-bit little-endian number.
func (r *Reader) Int64() int64 {
	return int64(r.Uint64())
}

// Discard skips the next n bytes.
func (r *Reader) Discard(n int) (discarded int, err error) {
	if n < 0 {
		return 0, errNegativeCount
	}
	for discarded < n {
		if r.pos >= r.nlim {
			if err = r.fill(); err != nil {
				return discarded, err
			}
		}
		partial := min(r.nlim-r.pos, n-discarded)
		r.pos += partial
		discarded += partial
	}
	return discarded, nil
}

// Peek returns the internal buffer for next 'n' bytes if possible.
// The returned slice points to the internal buffer and is invalid after the next read.
func (r *Reader) Peek(n int) ([]byte, error) {
	if n < 0 {
		return nil, errNegativeCount
	}
	if n > r.bufSize {
		return nil, ErrBufferTooSmall
	}
	for r.nlim-r.pos < n {
		// A fill() on a sliding zero-copy view can return a short window
		// when the current position is near a page boundary (a borrowed
		// view never straddles pages). Keep filling while progress is
		// made, so a small view at the end of a page is combined with the
		// data from the next page.
		before := r.nbuf - r.pos
		if err := r.fill(); err != nil {
			if r.nbuf-r.pos == before {
				return nil, err
			}
			break
		}
		if r.nbuf-r.pos == before {
			break
		}
	}
	if r.nlim-r.pos < n {
		return nil, io.EOF
	}
	return r.buf[r.pos : r.pos+n], nil
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
		if i := bytes.IndexByte(r.buf[r.pos:r.nlim], delim); i >= 0 {
			res := r.buf[r.pos : r.pos+i]
			r.pos += i + 1
			return res, nil
		}

		if r.off >= r.slimit {
			res := r.buf[r.pos:r.nlim]
			r.pos = r.nlim
			return res, io.EOF
		}

		// If buffer is full and no delim, we must clear it to find the delim
		if r.nlim != r.nbuf || (r.pos == 0 && r.nbuf == r.bufSize) {
			pos := r.pos
			r.pos = r.nlim
			return r.buf[pos:r.nlim], ErrBufferTooSmall
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
		i := bytes.Index(r.buf[r.pos:r.nlim], pattern)
		if i >= 0 {
			matchStart := r.Tell() + int64(i)
			r.pos += i + plen // Advance cursor to AFTER the pattern
			return matchStart, nil
		}

		// Pattern not found; discard unmatched data, but keep up to (plen-1)
		// bytes to catch patterns split across buffer boundaries.
		r.pos = r.nlim - min(r.nlim-r.pos, plen-1)
		if err := r.fill(); err != nil {
			r.pos = r.nlim
			return -1, err
		}
	}
}

// StartSection modifies reader to process a section of the file of length 'n':
// further operations do go beyond the section until EndSection is called.
func (r *Reader) StartSection(n int64) error {
	if n < 0 {
		return errNegativeCount
	}
	if r.Remaining() < n {
		return io.ErrUnexpectedEOF
	}

	r.sectionEnds = append(r.sectionEnds, r.slimit)
	r.slimit = r.off - int64(r.nbuf-r.pos) + n
	r.updateBufferLimit()
	return nil
}

// EndSection ends a section.
func (r *Reader) EndSection() {
	oldEnd := r.sectionEnds[len(r.sectionEnds)-1]
	r.sectionEnds = r.sectionEnds[:len(r.sectionEnds)-1]

	if remaining := r.Remaining(); remaining > 0 {
		r.Discard(int(remaining))
	}
	r.slimit = oldEnd
	r.updateBufferLimit()
}
