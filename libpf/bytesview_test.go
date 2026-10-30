// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf_test

import (
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
)

func TestBytesView(t *testing.T) {
	b := libpf.NewBytesView([]byte("data-for-the-test"))

	// View from an offset extends up to the end of the slice.
	view, err := b.ViewAt(9, 4)
	require.NoError(t, err)
	require.Equal(t, []byte("the-test"), view)

	// Pinning is trivial: the same view, naturally stable.
	pinned, err := b.PinAt(9, 4)
	require.NoError(t, err)
	require.Equal(t, view, pinned)
	b.UnpinAt(9)

	// ReadAt transparency.
	buf := make([]byte, 4)
	_, err = b.ReadAt(buf, 9)
	require.NoError(t, err)
	require.Equal(t, []byte("the-"), buf)

	// Past the end.
	_, err = b.ViewAt(17, 1)
	require.ErrorIs(t, err, io.EOF)

	// minLen extending beyond the end.
	_, err = b.ViewAt(15, 4)
	require.ErrorIs(t, err, io.EOF)

	// Negative offset.
	_, err = b.ViewAt(-1, 1)
	require.Error(t, err)

	// Non-positive minLen is treated as one.
	view, err = b.ViewAt(9, 0)
	require.NoError(t, err)
	require.Equal(t, []byte("the-test"), view)
}
