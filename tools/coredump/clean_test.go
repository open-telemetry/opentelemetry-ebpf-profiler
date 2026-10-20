// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

func TestCleanTempFiles(t *testing.T) {
	for _, tc := range []struct {
		name     string
		args     []string
		wantKept bool
	}{
		{name: "default"},
		{name: "dry run", args: []string{"-dry-run"}, wantKept: true},
		{name: "temp disabled", args: []string{"-temp=false"}, wantKept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cacheDir := t.TempDir()
			store, err := modulestore.New(nil, "", "", cacheDir)
			require.NoError(t, err)

			temp, err := os.CreateTemp(cacheDir, "tmp.")
			require.NoError(t, err)
			require.NoError(t, temp.Close())

			err = newCleanCmd(store).ParseAndRun(t.Context(), tc.args)
			require.NoError(t, err)
			if tc.wantKept {
				require.FileExists(t, temp.Name())
			} else {
				require.NoFileExists(t, temp.Name())
			}
		})
	}
}
