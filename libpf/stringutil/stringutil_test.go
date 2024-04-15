/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package stringutil

import (
	"testing"
)

func TestFieldsN(t *testing.T) {
	tests := map[string]struct {
		input     string
		expected  []string
		maxFields int
	}{
		"empty":          {"", []string{}, 2},
		"only spaces":    {"  ", []string{}, 2},
		"1 field":        {"111", []string{"111"}, 2},
		"1 field B":      {" 111", []string{"111"}, 2},
		"1 field C":      {"111 ", []string{"111"}, 2},
		"1 field D":      {" 111 ", []string{"111"}, 2},
		"2 fields":       {"111 222", []string{"111", "222"}, 2},
		"3 fields cap 2": {"111 222  333", []string{"111", "222  333"}, 2},
		"3 fields cap 3": {"111 222  333", []string{"111", "222", "333"}, 3},
		"4 fields cap 2": {"111 222  333 444", []string{"111", "222  333 444"}, 2},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			var fields [4]string
			n := FieldsN(testcase.input, fields[:testcase.maxFields])
			if len(testcase.expected) != n {
				t.Fatalf("unexpected result1: %v\nexpected: %v", fields, testcase.expected)
			}
			for i := range testcase.expected {
				if testcase.expected[i] != fields[i] {
					t.Fatalf("unexpected result2: %v\nexpected: %v", fields, testcase.expected)
				}
			}
		})
	}
}

func TestSplitN(t *testing.T) {
	tests := map[string]struct {
		input     string
		expected  []string
		maxFields int
	}{
		"empty":          {"", []string{""}, 2},
		"only sep":       {"-", []string{"", ""}, 2},
		"1 field":        {"111", []string{"111"}, 2},
		"2 fields B":     {"-111", []string{"", "111"}, 2},
		"2 fields C":     {"111-", []string{"111", ""}, 2},
		"3 fields A":     {"-111-", []string{"", "111", ""}, 3},
		"3 fields B":     {"111-222", []string{"111", "222"}, 3},
		"4 fields cap 3": {"111-222--333", []string{"111", "222", "-333"}, 3},
		"4 fields cap 4": {"111-222--333", []string{"111", "222", "", "333"}, 4},
		"5 fields cap 3": {"111-222--333-444", []string{"111", "222", "-333-444"}, 3},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			var fields [4]string
			n := SplitN(testcase.input, "-", fields[:testcase.maxFields])
			if len(testcase.expected) != n {
				t.Fatalf("unexpected result (%d): %v\nexpected: %v", n, fields, testcase.expected)
			}
			for i := range testcase.expected {
				if testcase.expected[i] != fields[i] {
					t.Fatalf("unexpected result2: %v\nexpected: %v", fields, testcase.expected)
				}
			}
		})
	}
}

func TestByteSlice2String(t *testing.T) {
	var b [4]byte
	s := ByteSlice2String(b[:1]) // create s with length 1 and a 0 byte inside

	if s != "\x00" {
		t.Fatalf("Unexpected string '%s', expected '\x00'", s)
	}

	b[0] = 'a'
	if s != "a" {
		t.Fatalf("Unexpected string '%s', expected 'a'", s)
	}
}
