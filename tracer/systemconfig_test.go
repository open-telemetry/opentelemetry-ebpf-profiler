// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"
)

func TestResolvePIDNSTranslation(t *testing.T) {
	t.Run("off disables translation", func(t *testing.T) {
		enabled, dev, ino, err := resolvePIDNSTranslation("off")
		require.NoError(t, err)
		require.False(t, enabled)
		require.Zero(t, dev)
		require.Zero(t, ino)
	})

	t.Run("invalid mode errors", func(t *testing.T) {
		_, _, _, err := resolvePIDNSTranslation("sometimes")
		require.Error(t, err)
	})

	t.Run("on targets our own pid namespace", func(t *testing.T) {
		enabled, _, ino, err := resolvePIDNSTranslation("on")
		require.NoError(t, err)
		require.True(t, enabled)
		// The inode of a live nsfs namespace is always non-zero.
		require.NotZero(t, ino)
	})

	t.Run("auto matches nesting detection", func(t *testing.T) {
		nested, derr := runningInNestedPIDNamespace()
		require.NoError(t, derr)
		enabled, _, _, err := resolvePIDNSTranslation("auto")
		require.NoError(t, err)
		require.Equal(t, nested, enabled)
	})
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
