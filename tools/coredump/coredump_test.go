// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

func TestCoreDumps(t *testing.T) {
	cases, err := findTestCases(true)
	require.NoError(t, err)
	require.NotEmpty(t, cases)

	store, err := modulestore.InitModuleStore(localCachePath)
	require.NoError(t, err)

	for _, filename := range cases {
		filename := filename
		t.Run(filename, func(t *testing.T) {
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
