// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package testsupport // import "go.opentelemetry.io/ebpf-profiler/testsupport"

import (
	"errors"
	"os"
	"testing"
)

// RequireGeneratedTestFile verifies that a generated test fixture exists and
// provides an actionable failure message when it does not.
func RequireGeneratedTestFile(t *testing.T, path string) {
	t.Helper()

	_, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing generated test fixture %q; run `make test-deps` from the repository root", path)
	}
	if err != nil {
		t.Fatalf("stat %q: %v", path, err)
	}
}
