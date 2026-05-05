// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package types

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

func TestParseAllPlusExplicitSymtab(t *testing.T) {
	include, err := Parse("all,symtab")
	require.NoError(t, err)
	require.True(t, include.Has(SymtabTracer))
	require.True(t, include.Has(GoTracer), "all should still enable other tracers")
}

func TestParseTracers(t *testing.T) {
	for _, tt := range tracersTestsOK {
		in := tt.in
		t.Run(tt.in, func(t *testing.T) {
			include, err := Parse(in)
			require.NoError(t, err)

			if tt.expectedTracers == nil {
				for tracer := range maxTracers {
					if slices.Contains(excludedTracers, tracer) {
						require.False(t, include.Has(tracer),
							"%s must not be enabled by 'all'", tracer.String())
						continue
					}
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
			_, err := Parse(in)
			require.Error(t, err)
		})
	}
}

func availableOnArch(tracer tracerType) bool {
	switch runtime.GOARCH {
	case "amd64":
		return true
	case "arm64":
		return tracer != DotnetTracer
	default:
		panic("unsupported architecture")
	}
}
