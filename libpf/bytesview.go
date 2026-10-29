// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"fmt"
	"io"
)

// BytesView implements the ViewAtReader interface over an in-memory byte
// slice. Views alias the slice: they are stable for its lifetime, so
// pinning is trivial. It serves the trivial variant of the interface, and
// is meant for tests and in-memory data (e.g. an area decoded from another
// reader).
type BytesView struct {
	data []byte
}

// NewBytesView returns a BytesView serving zero-copy views of b.
func NewBytesView(b []byte) *BytesView {
	return &BytesView{data: b}
}

var _ ViewAtReader = &BytesView{}

// Len returns the length of the underlying byte slice.
func (b *BytesView) Len() int {
	return len(b.data)
}

// ReadAt implements the io.ReaderAt interface.
func (b *BytesView) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(b.data)) {
		return 0, io.EOF
	}
	n := copy(p, b.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ViewAt returns a zero-copy view of at least minLen bytes starting at
// offs. The view extends up to the end of the slice.
func (b *BytesView) ViewAt(offs, minLen int64) ([]byte, error) {
	if offs < 0 {
		return nil, fmt.Errorf("offset %d is out of bounds (len %d)", offs, len(b.data))
	}
	if offs >= int64(len(b.data)) || int64(len(b.data))-offs < minLen {
		return nil, io.EOF
	}
	return b.data[offs:], nil
}

// PinAt is trivial: the memory is stable for its lifetime.
func (b *BytesView) PinAt(offs, minLen int64) ([]byte, error) {
	return b.ViewAt(offs, minLen)
}

// UnpinAt is a no-op: the memory is stable for its lifetime.
func (b *BytesView) UnpinAt(offs int64) {}
