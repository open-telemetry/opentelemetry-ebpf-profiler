// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package modulestore

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUnpackModuleToPathRemovesFailedOutput(t *testing.T) {
	for _, name := range []string{"download error", "corrupt chunk"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input")
			contents := bytes.Repeat([]byte("module contents"), zstpakChunkSize)
			require.NoError(t, os.WriteFile(input, contents, 0o600))
			store, err := New(nil, "", "", filepath.Join(dir, "cache"))
			require.NoError(t, err)
			id, _, err := store.InsertModuleLocally(input)
			require.NoError(t, err)
			cachedPath := store.makeLocalPath(id)
			compressed, err := os.ReadFile(cachedPath)
			require.NoError(t, err)

			var goodServer *httptest.Server
			if name == "download error" {
				badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					w.WriteHeader(http.StatusServiceUnavailable)
				}))
				t.Cleanup(badServer.Close)
				goodServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
					_, _ = w.Write(compressed)
				}))
				t.Cleanup(goodServer.Close)
				store.publicReadURL = badServer.URL + "/"
				require.NoError(t, store.RemoveLocalModule(id))
			} else {
				// Keep the footer intact so extraction creates a full-size sparse file
				// before it fails to decompress the first chunk.
				corrupt := bytes.Clone(compressed)
				corrupt[0] ^= 0xff
				require.NoError(t, os.WriteFile(cachedPath, corrupt, 0o600))
			}

			output := filepath.Join(dir, "output")
			require.Error(t, store.UnpackModuleToPath(id, output))
			require.NoFileExists(t, output)

			// A retry after the module becomes available must produce the original data.
			if goodServer != nil {
				store.publicReadURL = goodServer.URL + "/"
			} else {
				require.NoError(t, os.WriteFile(cachedPath, compressed, 0o600))
			}
			require.NoError(t, store.UnpackModuleToPath(id, output))
			got, err := os.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, contents, got)
		})
	}
}

func TestUnpackModuleToPathKeepsExistingOutputOnFailure(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	contents := []byte("module contents")
	require.NoError(t, os.WriteFile(input, contents, 0o600))
	store, err := New(nil, "", "", filepath.Join(dir, "cache"))
	require.NoError(t, err)
	id, _, err := store.InsertModuleLocally(input)
	require.NoError(t, err)

	cachedPath := store.makeLocalPath(id)
	compressed, err := os.ReadFile(cachedPath)
	require.NoError(t, err)
	compressed[0] ^= 0xff
	require.NoError(t, os.WriteFile(cachedPath, compressed, 0o600))

	output := filepath.Join(dir, "output")
	require.NoError(t, os.WriteFile(output, []byte("previous"), 0o600))
	require.Error(t, store.UnpackModuleToPath(id, output))
	got, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, []byte("previous"), got)
}

func TestUnpackModuleToPathWritesThroughSymlink(t *testing.T) {
	dir := t.TempDir()
	input := filepath.Join(dir, "input")
	contents := []byte("module contents")
	require.NoError(t, os.WriteFile(input, contents, 0o600))
	store, err := New(nil, "", "", filepath.Join(dir, "cache"))
	require.NoError(t, err)
	id, _, err := store.InsertModuleLocally(input)
	require.NoError(t, err)

	target := filepath.Join(dir, "target")
	require.NoError(t, os.WriteFile(target, []byte("previous"), 0o640))
	link := filepath.Join(dir, "link")
	require.NoError(t, os.Symlink(target, link))

	require.NoError(t, store.UnpackModuleToPath(id, link))
	info, err := os.Lstat(link)
	require.NoError(t, err)
	require.NotZero(t, info.Mode()&os.ModeSymlink)

	got, err := os.ReadFile(target)
	require.NoError(t, err)
	require.Equal(t, contents, got)
}

func TestUnpackModuleToPathMode(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mode     os.FileMode
		existing bool
	}{
		{name: "new file", mode: 0o644},
		{name: "existing file", mode: 0o640, existing: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			input := filepath.Join(dir, "input")
			contents := []byte("module contents")
			require.NoError(t, os.WriteFile(input, contents, 0o600))
			store, err := New(nil, "", "", filepath.Join(dir, "cache"))
			require.NoError(t, err)
			id, _, err := store.InsertModuleLocally(input)
			require.NoError(t, err)

			output := filepath.Join(dir, "output")
			if tc.existing {
				require.NoError(t, os.WriteFile(output, []byte("previous"), tc.mode))
				require.NoError(t, os.Chmod(output, tc.mode))
			}
			require.NoError(t, store.UnpackModuleToPath(id, output))
			info, err := os.Stat(output)
			require.NoError(t, err)
			require.Equal(t, tc.mode, info.Mode().Perm())

			got, err := os.ReadFile(output)
			require.NoError(t, err)
			require.Equal(t, contents, got)
		})
	}
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
