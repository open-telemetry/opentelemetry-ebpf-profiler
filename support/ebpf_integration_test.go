//go:build integration && linux

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package support

import (
	"testing"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/open-telemetry/opentelemetry-ebpf-profiler/rlimit"

	"github.com/stretchr/testify/require"
)

// TestEbpf is a simplified version of the profiling agent.
// It takes the same eBPF ELF file (from ebpf/tracer.ebpf.x86)
// and loads it into the kernel. With this test, we can make sure,
// our eBPF code is loaded correctly and not rejected by the kernel.
// As this tests uses the BPF syscall, it is protected by the build tag integration.
func TestEbpf(t *testing.T) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	var coll *cebpf.CollectionSpec
	coll, err = LoadCollectionSpec()
	require.NoError(t, err)

	tracepointProbe, err := cebpf.NewProgram(coll.Programs["tracepoint__sys_enter_read"])
	require.NoError(t, err)
	defer func() {
		require.NoError(t, tracepointProbe.Close())
	}()

	hook, err := link.Tracepoint("syscalls", "sys_enter_read", tracepointProbe, nil)
	require.NoError(t, err)

	err = hook.Close()
	require.NoError(t, err)
}
