/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package main

import (
	"testing"

	"github.com/elastic/otel-profiling-agent/config"
)

// tests expected to succeed
var tracersTestsOK = []struct {
	in     string
	php    bool
	python bool
}{
	{"all", true, true},
	{"all,", true, true},
	{"all,native", true, true},
	{"native", false, false},
	{"native,php", true, false},
	{"native,python", false, true},
	{"native,php,python", true, true},
}

// tests expected to fail
var tracersTestsFail = []struct {
	in string
}{
	{"NNative"},
	{"foo"},
}

func TestParseTracers(t *testing.T) {
	for _, tt := range tracersTestsOK {
		tt := tt
		in := tt.in
		t.Run(tt.in, func(t *testing.T) {
			include, err := parseTracers(in)

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if tt.php != include[config.PHPTracer] {
				t.Errorf("Expected PHPTracer enabled by %s", in)
			}

			if tt.python != include[config.PythonTracer] {
				t.Errorf("Expected PythonTracer enabled by %s", in)
			}
		})
	}

	for _, tt := range tracersTestsFail {
		in := tt.in
		t.Run(tt.in, func(t *testing.T) {
			if _, err := parseTracers(in); err == nil {
				t.Errorf("Unexpected success with '%s'", in)
			}
		})
	}
}
