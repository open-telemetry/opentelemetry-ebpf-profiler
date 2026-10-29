// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf_test

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

// fakeViewReader is a simple libpf.ViewAtReader with a fixed contiguous
// region size, backed by an in-memory buffer. Views are only available
// within one region.
type fakeViewReader struct {
	data    []byte
	region  uint
	lastOff int64
}

func (f *fakeViewReader) ReadAt(p []byte, off int64) (int, error) {
	n := copy(p, f.data[off:])
	return n, nil
}

func (f *fakeViewReader) ViewAt(offs, minLen int64) ([]byte, error) {
	f.lastOff = offs
	if offs < 0 || uint64(offs) >= uint64(len(f.data)) {
		return nil, fmt.Errorf("offset out of range: %d", offs)
	}
	skip := uint64(offs) % uint64(f.region)
	if minLen <= 0 {
		minLen = 1
	}
	if skip+uint64(minLen) > uint64(f.region) {
		return nil, libpf.ErrNotContiguous
	}
	end := min(uint64(len(f.data)), uint64(offs)-skip+uint64(f.region))
	return f.data[offs:end], nil
}

func (f *fakeViewReader) PinAt(offs, minLen int64) ([]byte, error) {
	return f.ViewAt(offs, minLen)
}

func (f *fakeViewReader) UnpinAt(offs int64) {}

func TestInternFromView(t *testing.T) {
	data := []byte("hello world\000not part of the string\000and more data")
	// The NUL after 'more data' is at the end of the buffer.
	data = append(data, 0)

	v := &fakeViewReader{data: data, region: 8}
	check := func(offs, endOff int64, want string) {
		t.Helper()
		s, err := libpf.InternFromView(v, offs, endOff)
		require.NoError(t, err)
		require.Equal(t, want, s.String())
	}
	checkErr := func(offs, endOff int64) {
		t.Helper()
		s, err := libpf.InternFromView(v, offs, endOff)
		require.ErrorIs(t, err, libpf.ErrNoString)
		require.Equal(t, libpf.NullString, s)
	}

	check(0, min(int64(len(data)), int64(0)+4096), "hello world")
	check(12, min(int64(len(data)), int64(12)+4096), "not part of the string")

	// Bounded by endOff right after the terminator.
	check(0, 12, "hello world")
	// Bounded by endOff before the terminator.
	checkErr(0, 5)

	// endOff capped to a plausible string length (the former maxLen).
	checkErr(0, min(int64(len(data)), int64(0)+5))

	// String spanning multiple regions (region size 8, string starts at 12).
	check(12, min(int64(len(data)), int64(12)+4096), "not part of the string")

	// Invalid bounds.
	checkErr(-1, int64(len(data)))
	checkErr(5, 5)
	checkErr(5, 4)
	// endOff before any data (the former maxLen=0 case).
	checkErr(0, 0)

	// Unterminated string within bounds.
	checkErr(0, 11)

	// An empty string at a NUL terminator is valid: only the error
	// reports absence (e.g. the null section of an ELF).
	check(11, int64(len(data)), "")
	check(34, int64(len(data)), "")
	check(48, int64(len(data)), "")
}

func TestInternFromViewMultiRegion(t *testing.T) {
	// Build data with a string crossing many region boundaries.
	s := "this string definitely crosses several region boundaries"
	data := append([]byte(s), 0)
	v := &fakeViewReader{data: data, region: 8}
	check := func(offs, endOff int64, want string) {
		t.Helper()
		s, err := libpf.InternFromView(v, offs, endOff)
		require.NoError(t, err)
		require.Equal(t, want, s.String())
	}
	checkErr := func(offs, endOff int64) {
		t.Helper()
		_, err := libpf.InternFromView(v, offs, endOff)
		require.ErrorIs(t, err, libpf.ErrNoString)
	}

	check(0, int64(len(data)), s)

	// Same, but the string ends exactly at endOff with no NUL terminator.
	v = &fakeViewReader{data: data, region: 8}
	checkErr(0, int64(len(data))-1)

	// endOff capped exactly at the terminator position (the former
	// maxLen == string length case).
	v = &fakeViewReader{data: data, region: 8}
	check(0, int64(len(s))+1, s)
}

func TestUnsafeStringFromView(t *testing.T) {
	data := []byte("hello world\000not part of the string\000tail")
	v := &fakeViewReader{data: data, region: 8}

	// Single-view string: content matches, and it aliases the view.
	s, err := libpf.UnsafeStringFromView(v, 0, int64(len(data)))
	require.NoError(t, err)
	require.Equal(t, "hello world", s)

	// Multi-region string: spans views, and owns its memory.
	s, err = libpf.UnsafeStringFromView(v, 12, int64(len(data)))
	require.NoError(t, err)
	require.Equal(t, "not part of the string", s)

	// Bounds behave like StringFromView.
	_, err = libpf.UnsafeStringFromView(v, 5, 5)
	require.ErrorIs(t, err, libpf.ErrNoString)
	_, err = libpf.UnsafeStringFromView(v, 0, min(int64(len(data)), int64(0)+5))
	require.ErrorIs(t, err, libpf.ErrNoString)
	_, err = libpf.UnsafeStringFromView(v, 0, 11)
	require.ErrorIs(t, err, libpf.ErrNoString)

	// The unsafe and safe variants agree on all names in the data.
	for offs := range data {
		unsafeStr, unsafeErr := libpf.UnsafeStringFromView(v, int64(offs),
			min(int64(len(data)), int64(offs)+4096))
		safeStr, safeErr := libpf.StringFromView(v, int64(offs),
			min(int64(len(data)), int64(offs)+4096))
		require.Equal(t, safeErr, unsafeErr)
		if safeErr == nil {
			require.Equal(t, safeStr, unsafeStr)
		}
	}
}
