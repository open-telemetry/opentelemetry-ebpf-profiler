// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/process"

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

func TestFindJITRegion(t *testing.T) {
	execAnon := func(vaddr, length uint64) process.RawMapping {
		return process.RawMapping{
			Vaddr:  vaddr,
			Length: length,
			Flags:  elf.PF_R | elf.PF_X,
			Path:   "",
		}
	}
	anon := func(vaddr, length uint64) process.RawMapping {
		return process.RawMapping{
			Vaddr:  vaddr,
			Length: length,
			Flags:  0, // ---p (PROT_NONE)
			Path:   "",
		}
	}
	labeled := func(vaddr, length uint64, flags elf.ProgFlag) process.RawMapping {
		return process.RawMapping{
			Vaddr:  vaddr,
			Length: length,
			Flags:  flags,
			Path:   "[anon:Ruby:rb_yjit_reserve_addr_space]",
		}
	}
	fileBacked := func(vaddr, length uint64, path string) process.RawMapping {
		return process.RawMapping{
			Vaddr:  vaddr,
			Length: length,
			Flags:  elf.PF_R | elf.PF_X,
			Path:   path,
		}
	}

	tests := []struct {
		name      string
		mappings  []process.RawMapping
		wantStart uint64
		wantEnd   uint64
		wantFound bool
	}{
		{
			name:      "no mappings",
			mappings:  nil,
			wantFound: false,
		},
		{
			name: "only file-backed mappings",
			mappings: []process.RawMapping{
				fileBacked(0x400000, 0x1000, "/usr/bin/ruby"),
				fileBacked(0x7f0000, 0x2000, "/lib/libc.so.6"),
			},
			wantFound: false,
		},
		{
			name: "labeled JIT region (single mapping)",
			mappings: []process.RawMapping{
				fileBacked(0x400000, 0x1000, "/usr/bin/ruby"),
				labeled(0x7f17d99b9000, 0x8000000, 0),
			},
			wantStart: 0x7f17d99b9000,
			wantEnd:   0x7f17d99b9000 + 0x8000000,
			wantFound: true,
		},
		{
			name: "labeled JIT region with split mappings and holes",
			mappings: []process.RawMapping{
				fileBacked(0x400000, 0x1000, "/usr/bin/ruby"),
				labeled(0x7f17d99b9000, 0x15f000, elf.PF_R|elf.PF_X),
				labeled(0x7f17d9b18000, 0x119000, elf.PF_R|elf.PF_X),
				labeled(0x7f17d9c31000, 0x7d88000, 0),
			},
			wantStart: 0x7f17d99b9000,
			wantEnd:   0x7f17d9c31000 + 0x7d88000,
			wantFound: true,
		},
		{
			name: "heuristic fallback includes contiguous anonymous reservation",
			mappings: []process.RawMapping{
				fileBacked(0x400000, 0x1000, "/usr/bin/ruby"),
				execAnon(0x7f17d99b9000, 0x15f000),
				execAnon(0x7f17d9b18000, 0x119000),
				anon(0x7f17d9c31000, 0x7d88000),
			},
			wantStart: 0x7f17d99b9000,
			wantEnd:   0x7f17d9c31000 + 0x7d88000,
			wantFound: true,
		},
		{
			name: "heuristic fallback stops at gap before another anonymous executable mapping",
			mappings: []process.RawMapping{
				fileBacked(0x400000, 0x1000, "/usr/bin/ruby"),
				execAnon(0x7f0000100000, 0x4000),
				execAnon(0x7f0000200000, 0x8000),
			},
			wantStart: 0x7f0000100000,
			wantEnd:   0x7f0000100000 + 0x4000,
			wantFound: true,
		},
		{
			name: "labeled takes precedence over heuristic",
			mappings: []process.RawMapping{
				execAnon(0x1000000, 0x4000),
				labeled(0x7f0000000000, 0x3000000, 0),
			},
			wantStart: 0x7f0000000000,
			wantEnd:   0x7f0000000000 + 0x3000000,
			wantFound: true,
		},
		{
		        // $ ruby --yjit --yjit-mem-size=4 /app.rb
			// 55f02fc16000-55f02fc17000 r--p 00000000 00:b8 16600758                   /usr/local/bin/ruby"
			// 55f02fc17000-55f02fc18000 r-xp 00001000 00:b8 16600758                   /usr/local/bin/ruby"
			// 55f02fc18000-55f02fc19000 r--p 00002000 00:b8 16600758                   /usr/local/bin/ruby"
			// 55f02fc19000-55f02fc1a000 r--p 00002000 00:b8 16600758                   /usr/local/bin/ruby"
			// 55f02fc1a000-55f02fc1b000 rw-p 00003000 00:b8 16600758                   /usr/local/bin/ruby"
			// 55f058fa0000-55f059412000 rw-p 00000000 00:00 0                          [heap]"
			// 7f84e7a23000-7f84e7a5f000 r-xp 00000000 00:00 0 "
			// 7f84e7a5f000-7f84e7a60000 rw-p 00000000 00:00 0 "
			// 7f84e7a60000-7f84e7a62000 r-xp 00000000 00:00 0 "
			// 7f84e7a62000-7f84e7a63000 rw-p 00000000 00:00 0 "
			// 7f84e7a63000-7f84e7e23000 ---p 00000000 00:00 0 "
			// 7f84e8110000-7f84e8200000 rw-p 00000000 00:00 0 "
			name: "jit hole",
			mappings: []process.RawMapping{
				execAnon(0x7f84e7a23000, 0x7f84e7a5f000-0x7f84e7a23000),
				// rw-p hole
				execAnon(0x7f84e7a60000, 0x7f84e7a62000-0x7f84e7a60000),
			},
			wantStart: 0x7f84e7a23000,
			wantEnd:   0x7f84e7e23000,
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, found := findJITRegion(tt.mappings)
			if found != tt.wantFound {
				t.Errorf("found = %v, want %v", found, tt.wantFound)
				return
			}
			if !found {
				return
			}
			if start != tt.wantStart {
				t.Errorf("start = %#x, want %#x", start, tt.wantStart)
			}
			if end != tt.wantEnd {
				t.Errorf("end = %#x, want %#x", end, tt.wantEnd)
			}
		})
	}
}
