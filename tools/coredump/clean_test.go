// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
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

func TestCleanTempFilesPermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove files from a read-only directory")
	}

	cacheDir := t.TempDir()
	store, err := modulestore.New(nil, "", "", cacheDir)
	require.NoError(t, err)

	temp, err := os.CreateTemp(cacheDir, "tmp.")
	require.NoError(t, err)
	require.NoError(t, temp.Close())

	require.NoError(t, os.Chmod(cacheDir, 0o555))
	t.Cleanup(func() {
		require.NoError(t, os.Chmod(cacheDir, 0o750))
	})

	err = newCleanCmd(store).ParseAndRun(t.Context(), nil)
	require.EqualError(t, err, "failed to delete temp files: failed to remove 1 temporary files")
	require.FileExists(t, temp.Name())
}

func TestCleanTempFilesContinuesAfterErrors(t *testing.T) {
	cacheDir := t.TempDir()
	store, err := modulestore.New(nil, "", "", cacheDir)
	require.NoError(t, err)

	for _, name := range []string{"tmp.a", "tmp.b"} {
		dir := filepath.Join(cacheDir, name)
		require.NoError(t, os.Mkdir(dir, 0o750))
		require.NoError(t, os.WriteFile(filepath.Join(dir, "keep"), nil, 0o600))
	}
	temp := filepath.Join(cacheDir, "tmp.z")
	require.NoError(t, os.WriteFile(temp, nil, 0o600))

	err = newCleanCmd(store).ParseAndRun(t.Context(), nil)
	require.EqualError(t, err, "failed to delete temp files: failed to remove 2 temporary files")
	require.NoFileExists(t, temp)
}
