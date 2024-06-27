/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package config

import (
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// tests expected to succeed
var tracersTestsOK = []struct {
	in              string
	expectedTracers []tracerType
}{
	{"all", nil},
	{"all,", nil},
	{"all,native", nil},
	{"native", []tracerType{}},
	{"native,php", []tracerType{PHPTracer}},
	{"native,python", []tracerType{PythonTracer}},
	{"native,php,python", []tracerType{PHPTracer, PythonTracer}},
	{"dotnet,ruby", []tracerType{DotnetTracer, RubyTracer}},
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
		in := tt.in
		t.Run(tt.in, func(t *testing.T) {
			include, err := ParseTracers(in)
			require.NoError(t, err)

			if tt.expectedTracers == nil {
				for tracer := range maxTracers {
					if availableOnArch(tracer) {
						require.True(t, include.Has(tracer))
					} else {
						require.False(t, include.Has(tracer))
					}
				}
				return
			}

			expected := strings.Split(in, ",")
			for tracer := range maxTracers {
				if slices.Contains(expected, tracer.String()) && availableOnArch(tracer) {
					require.True(t, include.Has(tracer))
				} else {
					require.False(t, include.Has(tracer))
				}
			}
		})
	}

	for _, tt := range tracersTestsFail {
		in := tt.in
		t.Run(tt.in, func(t *testing.T) {
			_, err := ParseTracers(in)
			require.Error(t, err)
		})
	}
}

func availableOnArch(tracer tracerType) bool {
	switch runtime.GOARCH {
	case "amd64":
		return true
	case "arm64":
		return tracer != V8Tracer && tracer != DotnetTracer
	default:
		panic("unsupported architecture")
	}
}
