// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"
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
	dev, ino, err := getCurrentNS(procSelfNsPid)
	require.NoError(t, err)
	require.NotZero(t, dev, "pid namespace device should be non-zero")
	require.NotZero(t, ino, "pid namespace inode should be non-zero")
}

func TestValidateSystemAnalysisResult(t *testing.T) {
	address := libpf.SymbolValue(0x1234)

	t.Run("not handled", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{Pid: 77}, address)
		require.Error(t, err)
		require.ErrorIs(t, err, errSystemAnalysisNotHandled)
		require.ErrorContains(t, err, "pid 77")
	})

	t.Run("helper failure", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{Err: -14}, address)
		require.Error(t, err)
		require.True(t, errors.Is(err, errSystemAnalysisFailed))
		require.ErrorContains(t, err, "helper err=-14")
	})

	t.Run("success", func(t *testing.T) {
		err := validateSystemAnalysisResult(support.SystemAnalysis{}, address)
		require.NoError(t, err)
	})
}

func TestCalculateFieldOffsetFindsAnonymousCompositeMembers(t *testing.T) {
	u64Type := &btf.Int{Name: "u64", Size: 8}
	vmArea := &btf.Struct{
		Name: "vm_area_struct",
		Size: 64,
		Members: []btf.Member{
			{
				Name:   "vm_start",
				Type:   u64Type,
				Offset: btf.Bits(0),
			},
			{
				Type: &btf.Union{
					Size: 16,
					Members: []btf.Member{
						{
							Type: &btf.Struct{
								Size: 16,
								Members: []btf.Member{
									{
										Name:   "vm_flags",
										Type:   u64Type,
										Offset: btf.Bits(64),
									},
								},
							},
						},
					},
				},
				Offset: btf.Bits(128),
			},
		},
	}

	offset, err := calculateFieldOffset(vmArea, "vm_flags")
	require.NoError(t, err)
	require.Equal(t, uint(24), offset)
}
