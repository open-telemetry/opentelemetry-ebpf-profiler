/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

// NOTE: temporarily disabled until we figured out how to best do this without S3 in the OTel env

//nolint:gocritic
//func TestCoreDumps(t *testing.T) {
//	cases, err := findTestCases(true)
//	require.NoError(t, err)
//	require.NotEmpty(t, cases)
//
//	store, err := initModuleStore()
//	require.NoError(t, err)
//
//	for _, filename := range cases {
//		filename := filename
//		t.Run(filename, func(t *testing.T) {
//			testCase, err := readTestCase(filename)
//			require.NoError(t, err)
//
//			ctx := context.Background()
//
//			core, err := OpenStoreCoredump(store, testCase.CoredumpRef, testCase.Modules)
//			require.NoError(t, err)
//			defer core.Close()
//
//			data, err := ExtractTraces(ctx, core, false, nil)
//
//			require.NoError(t, err)
//			require.Equal(t, testCase.Threads, data)
//		})
//	}
//}
