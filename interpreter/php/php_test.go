/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package php

import "testing"

func TestPHPRegexs(t *testing.T) {
	shouldMatch := []string{"php", "./php", "/foo/bar/php", "./foo/bar/php", "php-fpm", "php-cgi7"}
	for _, s := range shouldMatch {
		if !phpRegex.MatchString(s) {
			t.Fatalf("PHP regex %s should match %s", phpRegex.String(), s)
		}
	}

	shouldNotMatch := []string{"foophp", "ph p", "ph/p", "php-bar"}
	for _, s := range shouldNotMatch {
		if phpRegex.MatchString(s) {
			t.Fatalf("regex %s should not match %s", phpRegex.String(), s)
		}
	}
}

func version(major, minor, release uint) uint {
	return major*0x10000 + minor*0x100 + release
}

func TestVersionExtract(t *testing.T) {
	tests := map[string]struct {
		given       string
		expected    uint
		expectError bool
	}{
		"7.x":          {given: "7.4.19", expected: version(7, 4, 19), expectError: false},
		"8.x":          {given: "8.2.7", expected: version(8, 2, 7), expectError: false},
		"double-digit": {given: "8.0.27", expected: version(8, 0, 27), expectError: false},
		"suffix": {
			given:       "8.1.2-1ubuntu2.14",
			expected:    version(8, 1, 2),
			expectError: false,
		},
		"no-release":   {given: "7.4", expected: 0, expectError: true},
		"trailing-dot": {given: "8.0.", expected: 0, expectError: true},
		"only-major":   {given: "8", expected: 0, expectError: true},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			v, err := VersionExtract(test.given)
			if v != test.expected {
				t.Fatalf("Expected %v, got %v", test.expected, v)
			}
			if test.expectError && err == nil {
				t.Fatalf("Expected error, received no error")
			}
			if test.expectError == false && err != nil {
				t.Fatalf("Expected no error, received error: %v", err)
			}
		})
	}
}
