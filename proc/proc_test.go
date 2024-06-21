/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package proc

import (
	"testing"

	"github.com/elastic/otel-profiling-agent/libpf"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func assertSymbol(t *testing.T, symmap *libpf.SymbolMap, name libpf.SymbolName,
	expectedAddress libpf.SymbolValue) {
	sym, err := symmap.LookupSymbol(name)
	require.NoError(t, err)
	assert.Equal(t, expectedAddress, sym.Address)
}

func TestParseKallSyms(t *testing.T) {
	// Check parsing as if we were non-root
	symmap, err := GetKallsyms("testdata/kallsyms_0")
	require.Error(t, err)
	require.Nil(t, symmap)

	// Check parsing invalid file
	symmap, err = GetKallsyms("testdata/kallsyms_invalid")
	require.Error(t, err)
	require.Nil(t, symmap)

	// Happy case
	symmap, err = GetKallsyms("testdata/kallsyms")
	require.NoError(t, err)
	require.NotNil(t, symmap)

	assertSymbol(t, symmap, "cpu_tss_rw", 0x6000)
	assertSymbol(t, symmap, "hid_add_device", 0xffffffffc033e550)
}
