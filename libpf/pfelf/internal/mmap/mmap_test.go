package mmap_test

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf/internal/mmap"
)

func TestViewAt(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), t.Name()+".testfile")
	require.NoError(t, err)
	defer os.Remove(f.Name())

	testData := []byte("data-for-the-test")
	fmt.Fprintf(f, "%s", testData)
	mf, err := mmap.Open(f.Name())
	require.NoError(t, err)
	defer mf.Close()

	// View from an offset extends up to the end of the mapping.
	view, err := mf.ViewAt(9, 4)
	require.NoError(t, err)
	assert.Equal(t, testData[9:], view)

	// Past the end.
	view, err = mf.ViewAt(int64(len(testData)), 1)
	require.ErrorIs(t, err, io.EOF)
	assert.Nil(t, view)

	// minLen extending beyond the end.
	_, err = mf.ViewAt(int64(len(testData))-2, 4)
	require.ErrorIs(t, err, io.EOF)

	// Negative offset.
	_, err = mf.ViewAt(-1, 1)
	require.Error(t, err)

	// Non-positive minLen is treated as one.
	view, err = mf.ViewAt(9, 0)
	require.NoError(t, err)
	assert.Equal(t, testData[9:], view)

	// Pinning is trivial: the same view, naturally stable.
	pinned, err := mf.PinAt(9, 4)
	require.NoError(t, err)
	assert.Equal(t, testData[9:], pinned)
	mf.UnpinAt(9)
}
