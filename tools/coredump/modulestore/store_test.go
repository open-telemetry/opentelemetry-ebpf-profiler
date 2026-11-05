// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package modulestore

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnpackModuleToPath(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	contents := bytes.Repeat([]byte("module contents"), 1024)
	require.NoError(t, os.WriteFile(input, contents, 0o600))
	store, err := New(nil, "", "", filepath.Join(dir, "cache"))
	require.NoError(t, err)
	id, _, err := store.InsertModuleLocally(input)
	require.NoError(t, err)

	output := filepath.Join(dir, "output")
	require.NoError(t, store.UnpackModuleToPath(id, output))
	got, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, contents, got)

	compressed, err := os.OpenFile(store.makeLocalPath(id), os.O_WRONLY, 0)
	require.NoError(t, err)
	_, err = compressed.WriteAt([]byte{0}, 0)
	require.NoError(t, err)
	require.NoError(t, compressed.Close())

	err = store.UnpackModuleToPath(id, output)
	require.ErrorContains(t, err, "failed to read module")
	require.NoFileExists(t, output)
}

func TestInsertModuleLocallyClosesInput(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	require.NoError(t, os.WriteFile(input, []byte("module contents"), 0o600))
	store, err := New(nil, "", "", filepath.Join(dir, "cache"))
	require.NoError(t, err)

	for _, tc := range []struct {
		name    string
		path    string
		wantNew bool
		wantErr bool
	}{
		{name: "new module", path: input, wantNew: true},
		{name: "cached module", path: input},
		{name: "read error", path: dir, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, isNew, err := store.InsertModuleLocally(tc.path)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.wantNew, isNew)
			}

			fds, err := os.ReadDir("/proc/self/fd")
			require.NoError(t, err)
			for _, fd := range fds {
				target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
				if os.IsNotExist(err) {
					continue
				}
				require.NoError(t, err)
				require.NotEqual(t, tc.path, target, "input file descriptor is still open")
			}
		})
	}
}
