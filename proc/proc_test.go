// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"bufio"
	"bytes"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"

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

func TestParseKernelModules(t *testing.T) {
	content := []byte(`i40e 589824 - - Live 0xffffffffc0321000
mpt3sas 405504 - - Live 0xffffffffc02ab000
ahci 45056 - - Live 0xffffffffc0294000
libahci 49152 - - Live 0xffffffffc027f000
sp5100_tco 12288 - - Live 0xffffffffc0274000
watchdog 40960 - - Live 0xffffffffc025f000
k10temp 12288 - - Live 0xffffffffc0254000`)

	kmods, err := parseKernelModules(bufio.NewScanner(bytes.NewReader(content)))
	require.NoError(t, err)

	require.Len(t, kmods, 7)
	require.Equal(t, []kernelModule{
		{
			name:    "i40e",
			size:    589824,
			address: 0xffffffffc0321000,
		},
		{
			name:    "mpt3sas",
			size:    405504,
			address: 0xffffffffc02ab000,
		},
		{
			name:    "ahci",
			size:    45056,
			address: 0xffffffffc0294000,
		},
		{
			name:    "libahci",
			size:    49152,
			address: 0xffffffffc027f000,
		},
		{
			name:    "sp5100_tco",
			size:    12288,
			address: 0xffffffffc0274000,
		},
		{
			name:    "watchdog",
			size:    40960,
			address: 0xffffffffc025f000,
		},
		{
			name:    "k10temp",
			size:    12288,
			address: 0xffffffffc0254000,
		},
	}, kmods)
}

func TestParseKernelModuleLine(t *testing.T) {
	line := "i40e 589824 - - Live 0xffffffffc0364000"
	kmod, err := parseKernelModuleLine(line)
	require.NoError(t, err)
	require.Equal(t, kernelModule{
		name:    "i40e",
		size:    589824,
		address: 0xffffffffc0364000,
	}, kmod)
}
