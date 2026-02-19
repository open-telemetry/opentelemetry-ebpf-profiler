// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfatbuf_test

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/libpf/pfatbuf"
	"go.opentelemetry.io/ebpf-profiler/testsupport"
)

func testVariant(t *testing.T, fileSize uint) {
	file := testsupport.GenerateTestInputFile(255, fileSize)
	rawReader := bytes.NewReader(file)
	cachingReader := pfatbuf.Cache{}
	cachingReader.Init(rawReader)
	testsupport.ValidateReadAtWrapperTransparency(t, 10000, file, &cachingReader)
}

func TestCaching(t *testing.T) {
	for _, sz := range []uint{1024, 1346, 889} {
		t.Run(fmt.Sprintf("Size-%d", sz), func(t *testing.T) {
			testVariant(t, sz)
		})
	}
}

func TestOutOfBoundsTail(t *testing.T) {
	buf := bytes.NewReader([]byte{0, 1, 2, 3, 4, 5, 6, 7})
	r := pfatbuf.Cache{}
	r.Init(buf)
	b := make([]byte, 1)
	for i := range int64(32) {
		_, err := r.ReadAt(b, i)
		if i > 7 {
			require.ErrorIs(t, err, io.EOF)
		} else {
			require.NoError(t, err)
		}
	}
}
