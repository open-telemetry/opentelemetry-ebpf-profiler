/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetConfiguration(t *testing.T) {
	cfg := Config{
		ProjectID: 42,
	}

	// Test setting environment to "aws".
	err := SetConfiguration(&cfg)
	require.NoError(t, err)
}
