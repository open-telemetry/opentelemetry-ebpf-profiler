// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ruby // import "go.opentelemetry.io/ebpf-profiler/interpreter/ruby"

import (
	"debug/elf"
	"errors"
	"testing"
	"unsafe"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/interpreter"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/lpm"
	"go.opentelemetry.io/ebpf-profiler/process"
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type rubyTestEbpfHandler struct {
	interpreter.EbpfHandler
	calls             []string
	procDataUpdates   []support.RubyProcInfo
	mappingUpdates    int
	updateProcDataErr error
}

func (h *rubyTestEbpfHandler) UpdateProcData(_ libpf.InterpreterType, _ libpf.PID,
	data unsafe.Pointer,
) error {
	h.calls = append(h.calls, "proc-data")
	h.procDataUpdates = append(h.procDataUpdates, *(*support.RubyProcInfo)(data))
	return h.updateProcDataErr
}

func (h *rubyTestEbpfHandler) UpdatePidInterpreterMapping(_ libpf.PID, _ lpm.Prefix,
	_ uint8, _ host.FileID, _ uint64,
) error {
	h.calls = append(h.calls, "interpreter-mapping")
	h.mappingUpdates++
	return nil
}

type rubyTestProcess struct {
	process.Process
	pid libpf.PID
}

func (p *rubyTestProcess) PID() libpf.PID {
	return p.pid
}

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
	rwAnon := func(vaddr, length uint64) process.RawMapping {
		return process.RawMapping{
			Vaddr:  vaddr,
			Length: length,
			Flags:  elf.PF_R | elf.PF_W,
			Path:   "",
		}
	}
	protNoneAnon := func(vaddr, length uint64) process.RawMapping {
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
			Path:   "[anon:Ruby:rb_jit_reserve_addr_space]",
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
				execAnon(0x7f17d99b9000, 0x15f000),
				rwAnon(0x7f17d9b18000, 0x1000),
				execAnon(0x7f17d9b19000, 0x118000),
				protNoneAnon(0x7f17d9c31000, 0x7d88000),
			},
			wantStart: 0x7f17d99b9000,
			wantEnd:   0x7f17d9c31000 + 0x7d88000,
			wantFound: true,
		},
		{
			name: "heuristic fallback spans gaps between anonymous executable mappings",
			mappings: []process.RawMapping{
				execAnon(0x7f0000100000, 0x4000),
				execAnon(0x7f0000200000, 0x8000),
			},
			wantStart: 0x7f0000100000,
			wantEnd:   0x7f0000200000 + 0x8000,
			wantFound: true,
		},
		{
			name: "heuristic fallback spans production-like discontiguous anonymous executable mappings",
			mappings: []process.RawMapping{
				execAnon(0x7a6b2ec00000, 0x800000),
				execAnon(0x7a6b337fb000, 0x800000),
				execAnon(0x7a6ba0639000, 0x267c000),
				execAnon(0x7a6d45bb0000, 0x1000),
			},
			wantStart: 0x7a6b2ec00000,
			wantEnd:   0x7a6d45bb0000 + 0x1000,
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
			name: "ruby --yjit --yjit-mem-size=4 with rw holes and PROT_NONE tail",
			// $ ruby --yjit --yjit-mem-size=4 /app.rb
			// 7f84e7a23000-7f84e7a5f000 r-xp 00000000 00:00 0
			// 7f84e7a5f000-7f84e7a60000 rw-p 00000000 00:00 0
			// 7f84e7a60000-7f84e7a62000 r-xp 00000000 00:00 0
			// 7f84e7a62000-7f84e7a63000 rw-p 00000000 00:00 0
			// 7f84e7a63000-7f84e7e23000 ---p 00000000 00:00 0
			// 7f84e8110000-7f84e8200000 rw-p 00000000 00:00 0
			mappings: []process.RawMapping{
				execAnon(0x7f84e7a23000, 0x7f84e7a5f000-0x7f84e7a23000),
				rwAnon(0x7f84e7a5f000, 0x1000),
				execAnon(0x7f84e7a60000, 0x7f84e7a62000-0x7f84e7a60000),
				rwAnon(0x7f84e7a62000, 0x1000),
				protNoneAnon(0x7f84e7a63000, 0x7f84e7e23000-0x7f84e7a63000),
				rwAnon(0x7f84e8110000, 0x7f84e8200000-0x7f84e8110000),
			},
			wantStart: 0x7f84e7a23000,
			wantEnd:   0x7f84e7e23000,
			wantFound: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			start, end, found := findJITRegion(tt.mappings)
			if !assert.Equal(t, tt.wantFound, found) {
				return
			}
			if !found {
				return
			}
			assert.Equal(t, tt.wantStart, start)
			assert.Equal(t, tt.wantEnd, end)
		})
	}
}

func TestSynchronizeMappingsPublishesJITRangeBeforePrefixes(t *testing.T) {
	instance := &rubyInstance{
		procInfo: &support.RubyProcInfo{},
		prefixes: make(map[lpm.Prefix]uint32),
	}
	handler := &rubyTestEbpfHandler{}
	pr := &rubyTestProcess{pid: 123}
	mappings := []process.RawMapping{{
		Vaddr:  0x100000,
		Length: 0x10000,
		Flags:  elf.PF_R | elf.PF_X,
	}}

	require.NoError(t, instance.SynchronizeMappings(handler, nil, pr, mappings))
	require.NotEmpty(t, handler.calls)
	assert.Equal(t, "proc-data", handler.calls[0])
	assert.Greater(t, handler.mappingUpdates, 0)
	require.Len(t, handler.procDataUpdates, 1)
	assert.Equal(t, uint64(0x100000), handler.procDataUpdates[0].Jit_start)
	assert.Equal(t, uint64(0x110000), handler.procDataUpdates[0].Jit_end)
	assert.Equal(t, uint64(0x100000), instance.procInfo.Jit_start)
	assert.Equal(t, uint64(0x110000), instance.procInfo.Jit_end)
}

func TestSynchronizeMappingsRetriesProcDataAfterUpdateFailure(t *testing.T) {
	instance := &rubyInstance{
		procInfo: &support.RubyProcInfo{},
		prefixes: make(map[lpm.Prefix]uint32),
	}
	updateErr := errors.New("update proc data")
	handler := &rubyTestEbpfHandler{updateProcDataErr: updateErr}
	pr := &rubyTestProcess{pid: 123}
	mappings := []process.RawMapping{{
		Vaddr:  0x100000,
		Length: 0x10000,
		Flags:  elf.PF_R | elf.PF_X,
	}}

	require.ErrorIs(t, instance.SynchronizeMappings(handler, nil, pr, mappings), updateErr)
	assert.Equal(t, []string{"proc-data"}, handler.calls)
	assert.Zero(t, handler.mappingUpdates)
	assert.Zero(t, instance.procInfo.Jit_start)
	assert.Zero(t, instance.procInfo.Jit_end)

	handler.calls = nil
	handler.updateProcDataErr = nil
	require.NoError(t, instance.SynchronizeMappings(handler, nil, pr, mappings))
	require.NotEmpty(t, handler.calls)
	assert.Equal(t, "proc-data", handler.calls[0])
	assert.Greater(t, handler.mappingUpdates, 0)
}
