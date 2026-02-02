// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf_test

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestGetBuildIDFromNotesFile(t *testing.T) {
	buildID, err := pfelf.GetBuildIDFromNotesFile("testdata/the_notorious_build_id")
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString([]byte("_notorious_build_id_")), buildID)
}
