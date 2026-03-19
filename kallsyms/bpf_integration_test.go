//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kallsyms

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/rlimit"
)

const (
	eventuallyWaitFor = 10 * time.Second
	eventuallyTick    = 100 * time.Millisecond

	dynamicProgName     = "otel_dyn_test"
	preexistingProgName = "otel_pre_test"
)

// linearCPUs returns []int{0, 1, ..., n-1} for n online CPUs.
// This assumes contiguous CPU IDs, which is practical for integration tests.
// The proper parsing of /sys/devices/system/cpu/online lives in tracer/helper.go,
// but we don't want to export or duplicate it here.
func linearCPUs() []int {
	cpus := make([]int, runtime.NumCPU())
	for i := range cpus {
		cpus[i] = i
	}
	return cpus
}

// loadSocketFilter loads a minimal BPF socket filter program with the given name.
// The program simply returns 0. The caller is responsible for closing it.
func loadSocketFilter(t *testing.T, name string) *ebpf.Program {
	t.Helper()

	spec := &ebpf.ProgramSpec{
		Name:    name,
		Type:    ebpf.SocketFilter,
		License: "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	}

	prog, err := ebpf.NewProgram(spec)
	require.NoError(t, err)

	return prog
}

// findBPFSymbol searches the bpf module for a symbol whose kernel-assigned name
// ends with "_<progName>". Returns the full symbol name and its address.
func findBPFSymbol(s *bpfSymbolizer, progName string) (string, libpf.Address) {
	suffix := "_" + progName

	mod := s.Module()
	if mod == nil {
		return "", 0
	}

	for _, sym := range mod.symbols {
		name := mod.stringAt(sym.index)
		if strings.HasSuffix(name, suffix) {
			return name, mod.start + libpf.Address(sym.offset)
		}
	}
	return "", 0
}

// assertBPFSymbolFound polls the symbolizer until a BPF symbol matching progName
// appears, then verifies the full symbolization path (address -> module -> symbol).
func assertBPFSymbolFound(t *testing.T, s *Symbolizer, progName string) (string, libpf.Address) {
	t.Helper()

	var fullName string
	var progAddr libpf.Address
	require.Eventually(t, func() bool {
		fullName, progAddr = findBPFSymbol(s.bpf, progName)
		return fullName != ""
	}, eventuallyWaitFor, eventuallyTick,
		"BPF program with suffix %q not found by symbolizer", "_"+progName)

	t.Logf("Found BPF program %q at address 0x%x", fullName, progAddr)

	mod, err := s.GetModuleByAddress(progAddr)
	require.NoError(t, err)
	assert.Equal(t, "bpf", mod.Name())

	funcName, offset, err := mod.LookupSymbolByAddress(progAddr)
	require.NoError(t, err)
	assert.Equal(t, fullName, funcName)
	assert.Equal(t, uint(0), offset)

	funcName, offset, err = mod.LookupSymbolByAddress(progAddr + 1)
	require.NoError(t, err)
	assert.Equal(t, fullName, funcName)
	assert.Equal(t, uint(1), offset)

	return fullName, progAddr
}

// assertBPFSymbolRemoved polls the symbolizer until the BPF symbol matching
// progName disappears.
func assertBPFSymbolRemoved(t *testing.T, s *Symbolizer, progName string) {
	t.Helper()

	require.Eventually(t, func() bool {
		name, _ := findBPFSymbol(s.bpf, progName)
		return name == ""
	}, eventuallyWaitFor, eventuallyTick,
		"BPF program with suffix %q not removed from symbolizer", "_"+progName)

	t.Logf("BPF program with suffix %q successfully removed from symbolizer", "_"+progName)
}

// TestBPFSymbolizerDynamic verifies that programs loaded after the monitor
// starts are discovered via PERF_RECORD_KSYMBOL events and that unloading
// them removes the symbols.
func TestBPFSymbolizerDynamic(t *testing.T) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	s, err := NewSymbolizer()
	require.NoError(t, err)

	err = s.bpf.startMonitor(t.Context(), linearCPUs())
	require.NoError(t, err)
	defer s.bpf.Close()

	// The program hasn't been loaded yet, so the symbolizer must not know about it.
	name, _ := findBPFSymbol(s.bpf, dynamicProgName)
	require.Empty(t, name, "BPF program %q found before loading", dynamicProgName)

	prog := loadSocketFilter(t, dynamicProgName)

	fullName, _ := assertBPFSymbolFound(t, s, dynamicProgName)

	prog.Close()
	assertBPFSymbolRemoved(t, s, dynamicProgName)

	t.Logf("Dynamic test passed: %q added and removed", fullName)
}

// TestBPFSymbolizerPreexisting verifies that programs loaded before the
// monitor starts are discovered via the initial /proc/kallsyms parse.
func TestBPFSymbolizerPreexisting(t *testing.T) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	// Load the program before starting the monitor.
	prog := loadSocketFilter(t, preexistingProgName)

	s, err := NewSymbolizer()
	require.NoError(t, err)

	err = s.bpf.startMonitor(t.Context(), linearCPUs())
	require.NoError(t, err)
	defer s.bpf.Close()

	// The program was loaded before the monitor started, so it must be
	// discovered from /proc/kallsyms during the initial load.
	fullName, _ := assertBPFSymbolFound(t, s, preexistingProgName)
	t.Logf("Preexisting program %q found from initial kallsyms load", fullName)

	// Close the program and verify the symbol is removed via perf event.
	prog.Close()
	assertBPFSymbolRemoved(t, s, preexistingProgName)
	t.Logf("Preexisting program %q successfully removed", fullName)
}
