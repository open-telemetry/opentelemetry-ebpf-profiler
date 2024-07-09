/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSetConfiguration(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)

	cfg := Config{
		ProjectID:      42,
		CacheDirectory: cwd,
		SecretToken:    "secret",
		ValidatedTags:  "",
	}

	// Test setting environment to "aws".
	err = SetConfiguration(&cfg)
	require.NoError(t, err)

	cfg2 := cfg
	cfg2.SecretToken = ""
	err = SetConfiguration(&cfg2)
	require.Error(t, err)
}
