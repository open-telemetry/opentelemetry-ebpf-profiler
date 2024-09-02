// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

import (
	"testing"

	"github.com/open-telemetry/opentelemetry-ebpf-profiler/util"

	"github.com/stretchr/testify/assert"
)

func TestHexTo(t *testing.T) {
	tests := map[string]struct {
		result uint64
	}{
		"0":      {result: 0},
		"FFFFFF": {result: 16777215},
		"42":     {result: 66},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.result, util.HexToUint64(name))
		})
	}
}

func TestDecTo(t *testing.T) {
	tests := map[string]struct {
		result uint64
	}{
		"0":   {result: 0},
		"123": {result: 123},
		"42":  {result: 42},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.result, util.DecToUint64(name))
		})
	}
}

func TestIsValidString(t *testing.T) {
	tests := map[string]struct {
		input    []byte
		expected bool
	}{
		"empty":                    {input: []byte{}, expected: false},
		"control sequences":        {input: []byte{0x0, 0x1, 0x2, 0x3}, expected: false},
		"record separator":         {input: []byte{0x1E}, expected: false},
		"leading NULL":             {input: []byte{0x00, 'h', 'e', 'l', 'l', 'o'}, expected: false},
		"leading whitespace":       {input: []byte{'\t', 'h', 'e', 'l', 'l', 'o'}, expected: false},
		"trailing whitespace":      {input: []byte{'h', 'e', 'l', 'l', 'o', '\t'}, expected: false},
		"middle whitespace":        {input: []byte{'h', 'e', 'l', '\t', 'l', 'o'}, expected: false},
		"single word":              {input: []byte{'h', 'e', 'l', 'l', 'o'}, expected: true},
		"0xFF":                     {input: []byte{0xFF}, expected: false},
		"path":                     {input: []byte("/lib/foo/bar.so@64:123!"), expected: true},
		"日本語":                      {input: []byte("日本語"), expected: true},
		"emoji":                    {input: []byte{0xF0, 0x9F, 0x98, 0x8E}, expected: true},
		"invalid UTF-8 sequence 1": {input: []byte{0xE0, 0x76, 0x90}, expected: false},
		"invalid UTF-8 sequence 2": {input: []byte{0x80, 0x8F, 0x75}, expected: false},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.expected, util.IsValidString(string(testcase.input)))
		})
	}
}
