// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pfelf

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBuildIDFromNotesFile(t *testing.T) {
	r := bytes.NewReader([]byte("\x04\x00\x00\x00\x14\x00\x00\x00\x03\x00\x00\x00GNU\x00_notorious_build_id_"))
	buildID, err := getBuildIDFromNotesFile(r)
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString([]byte("_notorious_build_id_")), buildID)
}
