// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package elfunwindinfo

import (
	"os"
	"testing"
	"testing/fstest"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
	"go.opentelemetry.io/ebpf-profiler/testsupport"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestExtractDebugLink verifies that .gnu_debuglink is followed when the ELF
// has some .eh_frame basic blocks, but most of the code has unwind info only in
// the debug file. This is the case with musl on arm64.
func TestExtractDebugLink(t *testing.T) {
	testsupport.RequireGeneratedTestFile(t, "testdata/libdebuglink.so")
	testsupport.RequireGeneratedTestFile(t, "testdata/libdebuglink.so.debug")
	lib, err := os.ReadFile("testdata/libdebuglink.so")
	require.NoError(t, err)
	debug, err := os.ReadFile("testdata/libdebuglink.so.debug")
	require.NoError(t, err)

	ef, err := pfelf.Open("testdata/libdebuglink.so")
	require.NoError(t, err)
	defer ef.Close()
	sym, err := ef.LookupSymbol("debug_frame_only")
	require.NoError(t, err)
	addr := uint64(sym.Address)

	// Without the debug file, debug_frame_only has no unwind info. The fixture
	// has more basic blocks than the previous threshold of 8.
	intervals, err := extractFile(ef, nil)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(intervals.Blocks), 8)
	require.Nil(t, intervals.Find(addr))

	fsys := fstest.MapFS{
		"lib/libdebuglink.so":                     {Data: lib},
		"usr/lib/debug/lib/libdebuglink.so.debug": {Data: debug},
	}
	intervals, err = Extract(fsys, "lib/libdebuglink.so")
	require.NoError(t, err)
	assert.NotNil(t, intervals.Find(addr),
		"debug_frame_only should have unwind info from the .gnu_debuglink file")
}
