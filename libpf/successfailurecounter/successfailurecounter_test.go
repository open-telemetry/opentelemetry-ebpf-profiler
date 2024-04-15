/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package successfailurecounter

import (
	"sync/atomic"
	"testing"
)

func defaultToSuccess(t *testing.T, sfc SuccessFailureCounter, n int) {
	t.Helper()
	defer sfc.DefaultToSuccess()

	if n%2 == 0 {
		sfc.ReportSuccess()
	} else if n%3 == 0 {
		sfc.ReportFailure()
	}
}

func defaultToFailure(t *testing.T, sfc SuccessFailureCounter, n int) {
	t.Helper()
	defer sfc.DefaultToFailure()

	if n%2 == 0 {
		sfc.ReportSuccess()
	} else if n%3 == 0 {
		sfc.ReportFailure()
	}
}

func TestSuccessFailureCounter(t *testing.T) {
	tests := map[string]struct {
		call            func(*testing.T, SuccessFailureCounter, int)
		input           int
		expectedSucess  uint64
		expectedFailure uint64
	}{
		"default success - no report": {
			call:           defaultToSuccess,
			input:          1,
			expectedSucess: 1,
		},
		"default success - report success": {
			call:           defaultToSuccess,
			input:          2,
			expectedSucess: 1,
		},
		"default success - report failure": {
			call:            defaultToSuccess,
			input:           3,
			expectedFailure: 1,
		},
		"default failure - no report": {
			call:            defaultToFailure,
			input:           1,
			expectedFailure: 1,
		},
		"default failure - report success": {
			call:           defaultToFailure,
			input:          2,
			expectedSucess: 1,
		},
		"default failure - report failure": {
			call:            defaultToFailure,
			input:           3,
			expectedFailure: 1,
		},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			var success, failure atomic.Uint64
			sfc := New(&success, &failure)
			test.call(t, sfc, test.input)
			if test.expectedSucess != success.Load() {
				t.Fatalf("Expected success %d but got %d",
					test.expectedSucess, success.Load())
			}
			if test.expectedFailure != failure.Load() {
				t.Fatalf("Expected failure %d but got %d",
					test.expectedFailure, failure.Load())
			}
		})
	}
}
