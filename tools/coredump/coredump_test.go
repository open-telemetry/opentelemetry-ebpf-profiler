// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCoreDumps(t *testing.T) {
	var skip = map[string]bool{
		// https://github.com/open-telemetry/opentelemetry-ebpf-profiler/issues/416
		"testdata/amd64/alpine320-nobuildid.json": true,
		"testdata/amd64/alpine320.json":           true,
	}
	cases, err := findTestCases(true)
	require.NoError(t, err)
	require.NotEmpty(t, cases)

	store, err := initModuleStore()
	require.NoError(t, err)

	for _, filename := range cases {
		filename := filename
		t.Run(filename, func(t *testing.T) {
			if skip[filename] {
				t.Skip()
			}
			testCase, err := readTestCase(filename)
			require.NoError(t, err)

			ctx := context.Background()

			core, err := OpenStoreCoredump(store, testCase.CoredumpRef, testCase.Modules)
			require.NoError(t, err)
			defer core.Close()

			data, err := ExtractTraces(ctx, core, false, nil)

			require.NoError(t, err)
			require.Equal(t, testCase.Threads, data)
		})
	}
}
