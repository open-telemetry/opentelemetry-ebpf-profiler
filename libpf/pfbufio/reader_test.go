// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfbufio // import "go.opentelemetry.io/ebpf-profiler/libpf/pfbufio"

import (
	"bytes"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReader_BasicRead(t *testing.T) {
	data := []byte("0123456789abcdefghij")
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer PutReader(r)

	buf := make([]byte, 5)
	n, err := r.Read(buf)

	// Assertions
	require.NoError(t, err)
	assert.Equal(t, 5, n)
	assert.Equal(t, data[:5], buf)
	assert.Equal(t, int64(5), r.Tell())
}

func TestReader_SearchSlice(t *testing.T) {
	data := make([]byte, 10000)
	pattern := []byte("TARGET_DATA_HERE")
	copy(data[5000:], pattern)
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer PutReader(r)

	offset, err := r.SearchSlice(pattern)

	require.NoError(t, err)
	assert.Equal(t, int64(5000), offset)
	// Verify cursor is moved past the pattern
	assert.Equal(t, int64(5000+len(pattern)), r.Tell())
}

func TestReader_ReadByteAndDiscard(t *testing.T) {
	data := []byte("Hello World")
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer PutReader(r)

	// Read 'H'
	b, err := r.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte('H'), b)

	// Discard "ello "
	discarded, err := r.Discard(5)
	require.NoError(t, err)
	assert.Equal(t, 5, discarded)

	// Should be at 'W'
	b, err = r.ReadByte()
	require.NoError(t, err)
	assert.Equal(t, byte('W'), b)
}

func TestReader_EOF(t *testing.T) {
	data := []byte("Short")
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer PutReader(r)

	_, err := r.Discard(5)
	require.NoError(t, err)

	_, err = r.ReadByte()
	assert.ErrorIs(t, err, io.EOF)
}

func TestReader_ReadString(t *testing.T) {
	data := []byte("part1,part2,part3")
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer PutReader(r)

	str, err := r.ReadString(',')
	require.NoError(t, err)
	assert.Equal(t, "part1", str)
}

func TestReadSlice_CrossBoundary(t *testing.T) {
	a := bytes.Repeat([]byte("a"), bufferSize-10)
	b := bytes.Repeat([]byte("b"), 100)
	comma := []byte(",")
	data := slices.Concat(a, comma, b, comma)
	source := bytes.NewReader(data)

	r := NewReader(source, 0, int64(len(data)))
	defer PutReader(r)

	slice, err := r.ReadSlice(',')
	require.NoError(t, err)
	assert.Equal(t, a, slice)

	slice, err = r.ReadSlice(',')
	require.NoError(t, err)
	assert.Equal(t, b, slice)
}
