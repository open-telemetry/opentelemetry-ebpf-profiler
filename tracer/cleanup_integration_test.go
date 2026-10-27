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
		if target == "anon_inode:bpf-map" || target == "anon_inode:bpf-prog" ||
			target == "anon_inode:btf" {
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

	// The highest verifier log flag is BPF_LOG_FIXED (8), so the kernel rejects a
	// log level of 16 with EINVAL for every program. Programs are loaded after all
	// maps, so every map has been created by then and must not be left behind.
	cfg := &Config{
		InterpretersConfig:  interpreterconfig.AllInterpreters(),
		SamplesPerSecond:    20,
		BPFVerifierLogLevel: 1 << 4,
	}

	// Other tests in this package hold eBPF objects of their own, and the garbage
	// collector may release them at any point, so only require that the failed
	// initialization did not add to the count.
	before := countBPFObjects(t)
	ebpfMaps, ebpfProgs, _, err := initializeMapsAndPrograms(kmod, cfg,
		&originRegistry{}, &SysConfigVars{})
	require.ErrorContains(t, err, "failed to load unwinder eBPF programs")
	require.Nil(t, ebpfMaps)
	require.Nil(t, ebpfProgs)

	require.LessOrEqual(t, countBPFObjects(t), before,
		"failed initialization left eBPF objects loaded")
}
