// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/plugins/ruby"

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/stretchr/testify/assert"
)

func TestRubyRegex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		match   bool
		major   string
		minor   string
		release string
	}{
		{
			name:    "single_digit_version",
			input:   "libruby.so.3.2.1",
			match:   true,
			major:   "3",
			minor:   "2",
			release: "1",
		},
		{
			// https://github.com/ruby/ruby/releases/tag/v3_3_10
			name:    "multi_digit_release",
			input:   "libruby.so.3.3.10",
			match:   true,
			major:   "3",
			minor:   "3",
			release: "10",
		},
		{
			name:    "with_path",
			input:   "/usr/lib/libruby.so.3.3.10",
			match:   true,
			major:   "3",
			minor:   "3",
			release: "10",
		},
		{
			name:    "with_suffix",
			input:   "libruby-3.2.so.3.2.1",
			match:   true,
			major:   "3",
			minor:   "2",
			release: "1",
		},
		{
			name:  "no_match",
			input: "libpython.so.3.9",
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := libRubyRegex.FindStringSubmatch(tt.input)
			if !tt.match {
				assert.Nil(t, matches)
				return
			}
			if assert.NotNil(t, matches) {
				assert.Equal(t, tt.major, matches[1])
				assert.Equal(t, tt.minor, matches[2])
				assert.Equal(t, tt.release, matches[3])
			}
		})
	}
}

func TestRubyVersionRegex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		match   bool
		major   string
		minor   string
		release string
	}{
		{
			name:    "single_digit_version",
			input:   "3.2.1",
			match:   true,
			major:   "3",
			minor:   "2",
			release: "1",
		},
		{
			name:    "multi_digit_release",
			input:   "3.3.10",
			match:   true,
			major:   "3",
			minor:   "3",
			release: "10",
		},
		{
			name:  "no_match_partial",
			input: "3.9",
			match: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := rubyVersionRegex.FindStringSubmatch(tt.input)
			if !tt.match {
				assert.Nil(t, matches)
				return
			}
			if assert.NotNil(t, matches) {
				assert.Equal(t, tt.major, matches[1])
				assert.Equal(t, tt.minor, matches[2])
				assert.Equal(t, tt.release, matches[3])
			}
		})
	}
}

func TestQualifiedMethodName(t *testing.T) {
	tests := []struct {
		name       string
		classPath  string
		methodName string
		singleton  bool
		expected   string
	}{
		{
			name:       "no_class_not_singleton",
			classPath:  "",
			methodName: "foo",
			singleton:  false,
			expected:   "foo",
		},
		{
			name:       "class_not_singleton",
			classPath:  "ClassA",
			methodName: "foo",
			singleton:  false,
			expected:   "ClassA#foo",
		},
		{
			name:       "class_with_singleton",
			classPath:  "ClassA",
			methodName: "foo",
			singleton:  true,
			expected:   "ClassA.foo",
		},
		{
			name:       "empty_returns_empty",
			classPath:  "",
			methodName: "",
			singleton:  false,
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			qualified := qualifiedMethodName(libpf.Intern(tt.classPath), libpf.Intern(tt.methodName), tt.singleton)
			assert.Equal(t, libpf.Intern(tt.expected), qualified)
		})
	}
}

func TestProfileFrameFullLabel(t *testing.T) {
	tests := []struct {
		name       string
		classPath  string
		label      string
		baseLabel  string
		methodName string
		singleton  bool
		expected   string
	}{
		{
			name:       "no_class_uses_label",
			classPath:  "",
			label:      "block in foo",
			baseLabel:  "foo",
			methodName: "foo",
			singleton:  false,
			expected:   "block in foo",
		},
		{
			name:       "no_method_uses_label",
			classPath:  "",
			label:      "block in foo",
			baseLabel:  "foo",
			methodName: "",
			singleton:  false,
			expected:   "block in foo",
		},
		{
			name:       "no_class_no_base_label_no_method_uses_label",
			classPath:  "",
			label:      "block in foo",
			baseLabel:  "",
			methodName: "",
			singleton:  false,
			expected:   "block in foo",
		},
		{
			name:       "class_uses_label_prefix",
			classPath:  "ClassA",
			label:      "block in foo",
			baseLabel:  "foo",
			methodName: "foo",
			singleton:  false,
			expected:   "block in ClassA#foo",
		},
		{
			name:       "class_uses_label_prefix_singleton",
			classPath:  "ClassA",
			label:      "block in foo",
			baseLabel:  "foo",
			methodName: "foo",
			singleton:  true,
			expected:   "block in ClassA.foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fullLabel := profileFrameFullLabel(libpf.Intern(tt.classPath), libpf.Intern(tt.label), libpf.Intern(tt.baseLabel), libpf.Intern(tt.methodName), tt.singleton, false)
			assert.Equal(t, libpf.Intern(tt.expected), fullLabel)
		})
	}
}
