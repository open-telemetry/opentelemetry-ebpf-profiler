//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"os"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/interpreter/interpreterconfig"
	"go.opentelemetry.io/ebpf-profiler/kallsyms"
)

// countBPFObjects returns how many eBPF objects this process currently holds open.
// Maps and programs are anonymous inodes, so the link target of the file descriptor
// identifies them.
func countBPFObjects(t *testing.T) int {
	t.Helper()

	entries, err := os.ReadDir("/proc/self/fd")
	require.NoError(t, err)

	n := 0
	for _, entry := range entries {
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		// The descriptor may be gone by the time it is read, which is not an error.
		target, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil {
			continue
		}
		if target == "anon_inode:bpf-map" || target == "anon_inode:bpf-prog" {
			n++
		}
	}
	return n
}

// TestInitializeMapsAndProgramsCleansUpOnFailure checks that a failed setup does not
// leave eBPF objects loaded in the kernel. The collector may keep running after the
// error depending on its error mode, so whatever was loaded before the failure has to
// be released rather than left for the garbage collector to reclaim.
func TestInitializeMapsAndProgramsCleansUpOnFailure(t *testing.T) {
	symbolizer, err := kallsyms.NewSymbolizer()
	require.NoError(t, err)
	defer symbolizer.Close()

	kmod, err := symbolizer.Snapshot().GetModuleByName(kallsyms.Kernel)
	require.NoError(t, err)

	// Sizing the trace_events ring buffer from a zero sample rate gives it a single
	// byte, which the kernel rejects because a ring buffer has to be a page aligned
	// power of two. Exactly one map fails, so the maps created before it are what
	// must not be left behind.
	//
	// Which map is created first is up to the iteration order of the collection, so
	// run the whole initialization a few times: a single run could, in principle,
	// fail on the very first map and leave nothing to clean up.
	cfg := &Config{
		InterpretersConfig: interpreterconfig.AllInterpreters(),
		SamplesPerSecond:   0,
	}

	for range 5 {
		// Other tests in this package hold eBPF objects of their own, and the
		// garbage collector may release them at any point, so sample the count
		// for every attempt and only require that the failed initialization did
		// not add to it.
		before := countBPFObjects(t)
		ebpfMaps, ebpfProgs, _, err := initializeMapsAndPrograms(kmod, cfg,
			&originRegistry{}, &SysConfigVars{})
		require.Error(t, err)
		require.Nil(t, ebpfMaps)
		require.Nil(t, ebpfProgs)

		require.LessOrEqual(t, countBPFObjects(t), before,
			"failed initialization left eBPF objects loaded")
	}
}
