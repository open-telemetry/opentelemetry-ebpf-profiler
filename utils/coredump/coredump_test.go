/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import (
	"context"
	"testing"

	assert "github.com/stretchr/testify/require"
)

func TestCoreDumps(t *testing.T) {
	cases, err := findTestCases(true)
	assert.Nil(t, err)
	assert.NotEqual(t, len(cases), 0)

	store := initModuleStore()

	for _, filename := range cases {
		filename := filename
		t.Run(filename, func(t *testing.T) {
			testCase, err := readTestCase(filename)
			assert.Nil(t, err)

			ctx := context.Background()

			core, err := OpenStoreCoredump(store, testCase.CoredumpRef, testCase.Modules)
			if err != nil {
				t.SkipNow()
			}

			defer core.Close()
			data, err := ExtractTraces(ctx, core, false, nil)
			assert.Nil(t, err)
			assert.Equal(t, testCase.Threads, data)
		})
	}
}
