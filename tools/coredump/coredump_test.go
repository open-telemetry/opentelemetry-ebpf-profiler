// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/cloudstore"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

// parseFaultAddresses converts the hex/decimal address strings from a test
// case JSON into the uintptr-keyed map consumed by the ebpfContext. The int
// values are hit counters initialized to 0; ExtractTraces will fail the test
// if any remain 0 after the unwind. ParseUint with base=0 honors a "0x"
// prefix, so both "0x7f12..." and decimal forms work.
func parseFaultAddresses(t *testing.T, raw []string) map[uintptr]int {
	t.Helper()
	if len(raw) == 0 {
		return nil
	}
	out := make(map[uintptr]int, len(raw))
	for _, s := range raw {
		v, err := strconv.ParseUint(s, 0, 64)
		require.NoErrorf(t, err, "invalid fault-address %q", s)
		out[uintptr(v)] = 0
	}
	return out
}

func TestCoreDumps(t *testing.T) {
	cases, err := findTestCases(true)
	require.NoError(t, err)
	require.NotEmpty(t, cases)

	cloudClient, err := cloudstore.Client()
	require.NoError(t, err)
	store, err := modulestore.New(cloudClient,
		cloudstore.PublicReadURL(), cloudstore.ModulestoreS3Bucket(), "modulecache")
	require.NoError(t, err)

	for _, filename := range cases {
		t.Run(filename, func(t *testing.T) {
			testCase, err := readTestCase(filename)
			require.NoError(t, err)
			if testCase.Skip != "" {
				t.Skip(testCase.Skip)
			}

			core, err := OpenStoreCoredump(store, testCase.CoredumpRef, testCase.Modules)
			require.NoError(t, err)
			defer core.Close()

			faults := parseFaultAddresses(t, testCase.FaultAddresses)
			data, err := ExtractTraces(t.Context(), core, false, nil, faults)

			require.NoError(t, err)
			require.Equal(t, testCase.Threads, data)

			// Every fault address listed in the test case must have been
			// visited at least once by bpf_probe_read_user_with_test_fault;
			// otherwise the test isn't actually exercising the recovery path
			// it claims to (e.g. a stale address that the unwinder no longer
			// reads). The map is mutated in place by the helper, so we can
			// just iterate the post-run state.
			for addr, hits := range faults {
				require.Greaterf(t, hits, 0,
					"fault address 0x%x was never visited by "+
						"bpf_probe_read_user_with_test_fault", addr)
			}
		})
	}
}
