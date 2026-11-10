// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"bytes"
	"errors"
	"io"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfunsafe"
)

// ErrNotContiguous is returned by ViewAt if the requested range cannot be
// served from one contiguous region. Implementations are expected to make
// this determination without performing any I/O, and without populating
// their internal cache.
var ErrNotContiguous = errors.New("requested range is not contiguous within a single view")

// ErrNoString is returned by the string view helpers if a NUL-terminated
// string is not found within the given bounds, or offs is invalid. An
// empty string is a valid result: only the error reports absence.
var ErrNoString = errors.New("NUL-terminated string not found")

// PinHandle identifies an outstanding pinned view created by PinAt. The
// zero value is not a valid handle: Unpin with a zero, unknown or stale
// handle is a no-op.
type PinHandle uint64

// ViewAtReader extends the io.ReaderAt interface with a zero-copy view
// accessor. Implementations are typically backed by an internal cache or
// memory mapping.
type ViewAtReader interface {
	io.ReaderAt

	// ViewAt returns a zero-copy view of at least minLen bytes of data
	// starting at offs. The returned slice may be longer than minLen: it
	// usually extends up to the end of the implementation's contiguous
	// region (for example a cache page). Callers may use the extra bytes,
	// but must not rely on them being present.
	//
	// The view is backed by the internal storage of the reader, and is
	// only valid until the next read operation on the reader. The reader
	// must be used by a single consumer at a time.
	//
	// If the requested range cannot be served from one contiguous region,
	// ErrNotContiguous is returned. If offs is at or beyond the end of the
	// underlying data, io.EOF is returned. A non-positive minLen is
	// treated as one.
	ViewAt(offs, minLen int64) ([]byte, error)

	// PinAt returns a view like ViewAt, but pins the backing region: the
	// view stays valid even across other read operations, and the backing
	// storage will not be recycled. The returned handle must be released
	// exactly once with Unpin. Implementations with naturally stable
	// views (for example memory mappings) may pin trivially.
	PinAt(offs, minLen int64) ([]byte, PinHandle, error)

	// Unpin releases one pin, identified by a handle returned by PinAt.
	// Unknown, stale or zero handles are ignored.
	Unpin(h PinHandle)
}

// StableViewer is an optional interface that ViewAtReader implementations
// backed by naturally stable storage (for example memory mappings or
// in-memory data) may implement.
//
// Implementations serving views from evictable caches (for example page
// caches) must not implement it, as callers rely on StableViewAt views
// without any release obligation.
type StableViewer interface {
	// StableViewAt returns a zero-copy view of length bytes starting at
	// offs, valid until the reader is closed. It performs no I/O, and
	// carries no release obligation. It returns nil if the range is out
	// of bounds or the storage cannot be borrowed; callers must fall
	// back to copying in that case. A non-positive length is invalid.
	StableViewAt(offs, length int64) []byte
}

// stringFromView reads a NUL-terminated string at offs from v. The returned
// bool reports ownership of the returned memory: false for a transient view
// backing, true for a pooled buffer that the caller must copy and release
// with PutBuffer.
func stringFromView(v ViewAtReader, offs, endOff int64) ([]byte, bool, error) {
	if offs < 0 || offs >= endOff {
		return nil, false, ErrNoString
	}

	chunk, err := v.ViewAt(offs, 1)
	if err != nil {
		return nil, false, ErrNoString
	}
	if n := endOff - offs; n < int64(len(chunk)) {
		chunk = chunk[:n]
	}
	if idx := bytes.IndexByte(chunk, 0); idx >= 0 {
		return chunk[:idx], false, nil
	}

	// The string spans multiple views: assemble it into a pooled buffer.
	// Pooled buffers are larger than needed for a single string: the caller
	// must copy the result before releasing it.
	buf := GetBuffer(4096)
	used := len(chunk)
	copy(buf, chunk)
	offs += int64(len(chunk))
	for offs < endOff {
		chunk, err = v.ViewAt(offs, 1)
		if err != nil {
			break
		}
		if n := endOff - offs; n < int64(len(chunk)) {
			chunk = chunk[:n]
		}
		if idx := bytes.IndexByte(chunk, 0); idx >= 0 {
			if used+idx > len(buf) {
				break
			}
			copy(buf[used:], chunk[:idx])
			return buf[:used+idx], true, nil
		}
		if used+len(chunk) > len(buf) {
			break
		}
		copy(buf[used:], chunk)
		used += len(chunk)
		offs += int64(len(chunk))
	}
	PutBuffer(buf)
	return nil, false, ErrNoString
}

// UnsafeStringFromView reads a NUL-terminated string at offs from v, and
// returns it as a string without duplicating it. The string must be
// terminated before endOff (exclusive).
//
// The returned string may alias the internal storage of the reader: it is
// only valid until the next read operation on the reader, and the caller
// must clone it if it is kept any longer. Interning it with libpf.Intern is
// safe, as unique.Make clones the string on insertion. Strings spanning
// multiple views are assembled into a fresh buffer and own their memory.
// ErrNoString is returned if offs is invalid or the string is not
// terminated within the given bounds.
func UnsafeStringFromView(v ViewAtReader, offs, endOff int64) (string, error) {
	buf, pooled, err := stringFromView(v, offs, endOff)
	if err != nil {
		return "", err
	}
	if !pooled {
		return pfunsafe.ToString(buf), nil
	}
	// Pooling buffers are shared: the returned string must own its memory.
	str := string(buf)
	PutBuffer(buf)
	return str, nil
}

// StringFromView reads a NUL-terminated string at offs from v, and returns
// it as an allocated Go string. The string must be terminated before endOff
// (exclusive). ErrNoString is returned if offs is invalid or the string is
// not terminated within the given bounds.
func StringFromView(v ViewAtReader, offs, endOff int64) (string, error) {
	buf, pooled, err := stringFromView(v, offs, endOff)
	if err != nil {
		return "", err
	}
	str := string(buf)
	if pooled {
		PutBuffer(buf)
	}
	return str, nil
}

// InternFromView reads a NUL-terminated string at offs from v, and returns
// it interned. The string must be terminated before endOff (exclusive).
// ErrNoString is returned if offs is invalid or the string is not
// terminated within the given bounds. An empty string interns normally:
// only the error reports absence.
func InternFromView(v ViewAtReader, offs, endOff int64) (String, error) {
	buf, pooled, err := stringFromView(v, offs, endOff)
	if err != nil {
		return NullString, err
	}
	str := Intern(pfunsafe.ToString(buf))
	if pooled {
		PutBuffer(buf)
	}
	return str, nil
}
