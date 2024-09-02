// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package zstpak_test

import (
	"bytes"
	"os"
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/testsupport"
	zstpak "github.com/open-telemetry/opentelemetry-ebpf-profiler/tools/zstpak/lib"
	"github.com/stretchr/testify/require"
)

func generateInputFile(seqLen uint8, outputSize uint64) []byte {
	out := make([]byte, 0, outputSize)
	for i := uint64(0); i < outputSize; i++ {
		out = append(out, byte(i%uint64(seqLen)))
	}

	return out
}

func testRandomAccesses(t *testing.T, seqLen uint8, fileSize uint64,
	chunkSize uint64) {
	file := generateInputFile(seqLen, fileSize)
	reader := bytes.NewReader(file)

	temp, err := os.CreateTemp("", "")
	require.NoError(t, err)
	defer os.Remove(temp.Name())

	err = zstpak.CompressInto(reader, temp, chunkSize)
	require.NoError(t, err)
	err = temp.Close()
	require.NoError(t, err)

	zstReader, err := zstpak.Open(temp.Name())
	require.NoError(t, err)

	testsupport.ValidateReadAtWrapperTransparency(t, 1000, file, zstReader)
}

func TestRandomAccess(t *testing.T) {
	// Repeat with 3 sets of mostly arbitrarily chosen parameters.
	testRandomAccesses(t, 128, 1024, 64)
	testRandomAccesses(t, 43, 1424, 444)
	testRandomAccesses(t, 13, 1049454, 8543)
}
