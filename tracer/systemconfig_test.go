// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetCurrentNS_FileNotFound(t *testing.T) {
	_, _, err := getCurrentNS("/nonexistent/path/pid")
	require.Error(t, err)
	require.True(t, os.IsNotExist(err))
}

func TestGetCurrentNS_ProcSelfNsPid(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("skipping: /proc/self/ns/pid is Linux-specific (GOOS=%s)", runtime.GOOS)
	}
	const procSelfNsPid = "/proc/self/ns/pid"
	if _, err := os.Stat(procSelfNsPid); err != nil {
		t.Skipf("skipping: %s not available: %v", procSelfNsPid, err)
	}
	_, ino, err := getCurrentNS(procSelfNsPid)
	require.NoError(t, err)
	require.NotZero(t, ino, "pid namespace inode should be non-zero")
}

// TestParseBTFForNsTranslation verifies that namespace PID translation offsets
// can be resolved from kernel BTF when available. Skips when BTF is not present.
func TestParseBTFForNsTranslation(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("skipping: unsupported GOARCH=%s", runtime.GOARCH)
	}
	spec, err := loadBTFSpec()
	if err != nil {
		t.Skipf("skipping: kernel BTF not available: %v", err)
	}
	var vars sysConfigVars
	err = parseBTFForNsTranslation(&vars, spec)
	require.NoError(t, err)
	require.True(t, vars.ns_translation_enabled)
	require.Greater(t, vars.task_stack_offset, uint32(0))
	require.Greater(t, vars.task_nsproxy_off, uint32(0))
	require.Greater(t, vars.upid_size, uint32(0))
}
