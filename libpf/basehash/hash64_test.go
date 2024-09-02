// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package basehash

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBaseHash64(t *testing.T) {
	origHash := Hash64(5550100)

	// Test Sprintf
	marshaled := fmt.Sprintf("%x", origHash)
	expected := "54b014"
	assert.Equal(t, expected, marshaled)

	// Test (Un)MarshalJSON
	data, err := origHash.MarshalJSON()
	require.NoError(t, err)

	var newHash Hash64
	err = newHash.UnmarshalJSON(data)
	require.NoError(t, err)
	assert.Equal(t, origHash, newHash)
}
