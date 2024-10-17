// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"fmt"
	"runtime"
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

func printMemUsage() {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	fmt.Printf("Alloc = %v MiB", bToMb(m.Alloc))
	fmt.Printf("\tTotalAlloc = %v MiB", bToMb(m.TotalAlloc))
	fmt.Printf("\tSys = %v MiB", bToMb(m.Sys))
	fmt.Printf("\tNumGC = %v\n", m.NumGC)
}

func bToMb(b uint64) uint64 {
	return b / 1024 / 1024
}

func TestGetKallsymsMemoryUsage(t *testing.T) {
	fmt.Println("Memory usage before calling GetKallsyms:")
	printMemUsage()

	symmap, err := GetKallsyms("/proc/kallsyms")
	require.NoError(t, err)
	require.NotNil(t, symmap)

	fmt.Println("Memory usage after calling GetKallsyms:")
	printMemUsage()
}
