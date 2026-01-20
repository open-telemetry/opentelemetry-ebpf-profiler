// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"

	"github.com/stretchr/testify/assert"
)

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
