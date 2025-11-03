// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf_test

import (
	"debug/elf"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

var (
	// An ELF without DWARF symbols
	withoutDebugSymsPath = "testdata/without-debug-syms"
	// An ELF with DWARF symbols
	withDebugSymsPath = "testdata/with-debug-syms"
	// An ELF with only DWARF symbols
	separateDebugFile = "testdata/separate-debug-file"
)

func getELF(path string, t *testing.T) *elf.File {
	file, err := elf.Open(path)
	assert.NoError(t, err)
	return file
}

func TestGetBuildIDFromNotesFile(t *testing.T) {
	buildID, err := pfelf.GetBuildIDFromNotesFile("testdata/the_notorious_build_id")
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString([]byte("_notorious_build_id_")), buildID)
}
