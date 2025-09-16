// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/util"

	"github.com/stretchr/testify/assert"
)

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
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.expected, util.IsValidString(string(testcase.input)))
		})
	}
}

func TestSliceFromPointer(t *testing.T) {
	s := 0xcafebabe
	p := &s
	actual := SliceFromPointer(p)
	assert.Equal(t, []byte{0xbe, 0xba, 0xfe, 0xca, 0x0, 0x0, 0x0, 0x0}, actual)
	assert.Panics(t, func() {
		p = nil
		SliceFromPointer(p)
	})
}

func TestSliceFromSlice(t *testing.T) {
	s := []uint64{0xcafebabe, 0xdeadbeef}
	actual := SliceFromSlice(s)
	expected := []byte{
		0xbe, 0xba, 0xfe, 0xca, 0x0, 0x0, 0x0, 0x0,
		0xef, 0xbe, 0xad, 0xde, 0x0, 0x0, 0x0, 0x0,
	}
	assert.Equal(t, expected, actual)
	assert.NotPanics(t, func() {
		s = nil
		actual = SliceFromSlice(s)
		expected = nil
		assert.Equal(t, expected, actual)
		s = []uint64{}
		actual = SliceFromSlice(s)
		assert.Equal(t, expected, actual)
	})
}
