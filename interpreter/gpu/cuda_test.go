// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gpu_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/interpreter/gpu"
	"go.opentelemetry.io/ebpf-profiler/support"
)

// TestProgramNamesExist verifies that the eBPF program names used in cuda.go
// actually exist in the compiled eBPF collection. This catches bugs where
// the program names don't match the SEC() names in the .ebpf.c files.
func TestProgramNamesExist(t *testing.T) {
	// Load the eBPF collection
	coll, err := support.LoadCollectionSpec()
	require.NoError(t, err, "Failed to load eBPF collection spec")

	// Verify single-shot program names exist
	t.Run("SingleShotPrograms", func(t *testing.T) {
		progNames := []string{
			gpu.USDTProgCudaCorrelation,
			gpu.USDTProgCudaKernel,
		}

		for _, progName := range progNames {
			t.Run(progName, func(t *testing.T) {
				prog := coll.Programs[progName]
				require.NotNil(t, prog, "eBPF program %q not found in collection", progName)
				t.Logf("Found program %q", progName)
			})
		}
	})

	// Verify multi-attach program name exists
	t.Run("MultiAttachProgram", func(t *testing.T) {
		prog := coll.Programs[gpu.USDTProgCudaProbe]
		require.NotNil(t, prog, "eBPF program %q not found in collection", gpu.USDTProgCudaProbe)
		t.Logf("Found program %q", gpu.USDTProgCudaProbe)
	})
}
