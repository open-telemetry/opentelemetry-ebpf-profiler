// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/tools/coredump/modulestore"
)

func TestGdbRetriesFailedExtraction(t *testing.T) {
	for _, localPath := range []string{"/core", "/usr/bin/app"} {
		t.Run(filepath.Base(localPath), func(t *testing.T) {
			t.Chdir(t.TempDir())
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			defer server.Close()
			store, err := modulestore.New(nil, server.URL+"/", "", "modulecache")
			require.NoError(t, err)

			testCase := &CoredumpTestCase{}
			if localPath != "/core" {
				testCase.Modules = []ModuleInfo{{LocalPath: localPath}}
				corePath := filepath.Join(sysrootBaseDir, "case.json", "core")
				require.NoError(t, os.MkdirAll(filepath.Dir(corePath), 0o755))
				require.NoError(t, os.WriteFile(corePath, []byte("existing extraction"), 0o600))
			}
			require.NoError(t, writeTestCase("case.json", testCase, false))

			for attempt := int32(1); attempt <= 2; attempt++ {
				err = newGdbCmd(store).ParseAndRun(t.Context(), []string{"-extract-only", "-case", "case.json"})
				require.ErrorContains(t, err, "failed to unpack module")
				require.NoFileExists(t, filepath.Join(sysrootBaseDir, "case.json", localPath))
				require.Equal(t, attempt, requests.Load())
				if localPath != "/core" {
					data, err := os.ReadFile(filepath.Join(sysrootBaseDir, "case.json", "core"))
					require.NoError(t, err)
					require.Equal(t, "existing extraction", string(data))
				}
			}
		})
	}
}
