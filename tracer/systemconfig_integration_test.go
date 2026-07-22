//go:build integration && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/rlimit"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// TestLoadSelfHostNamespacePID verifies that the store_tracer_pid BPF program
// returns the host-namespace TGID of the current process. When tests run in the
// host PID namespace (the normal case), this must match os.Getpid().
func TestLoadSelfHostNamespacePID(t *testing.T) {
	restoreRlimit, err := rlimit.MaximizeMemlock()
	require.NoError(t, err)
	defer restoreRlimit()

	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err)

	pid, err := loadSelfHostNamespacePID(coll)
	require.NoError(t, err)
	require.Equal(t, uint32(os.Getpid()), pid,
		"BPF-reported host PID must match os.Getpid() when running in the host namespace")
}
