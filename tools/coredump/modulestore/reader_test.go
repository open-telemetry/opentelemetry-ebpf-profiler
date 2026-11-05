// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package modulestore

import (
	"bytes"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
)

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func TestModuleReaderReadStat(t *testing.T) {
	data := []byte("0123456789abcdef")
	m := &ModuleReader{
		ReaderAt: bytes.NewReader(data),
		Closer:   nopCloser{},
		name:     "module",
		size:     uint(len(data)),
	}

	buf := make([]byte, 5)
	n, err := m.Read(buf)
	require.NoError(t, err)
	require.Equal(t, []byte("01234"), buf[:n])

	rest, err := io.ReadAll(m)
	require.NoError(t, err)
	require.Equal(t, data[5:], rest)

	n, err = m.Read(buf)
	require.Equal(t, 0, n)
	require.ErrorIs(t, err, io.EOF)

	st, err := m.Stat()
	require.NoError(t, err)
	require.Equal(t, "module", st.Name())
	require.Equal(t, int64(len(data)), st.Size())
	require.False(t, st.IsDir())
}
