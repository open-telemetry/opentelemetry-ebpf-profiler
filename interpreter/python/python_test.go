// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"debug/elf"
	"os"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/libpf/pfelf"
)

func TestFrozenNameToFileName(t *testing.T) {
	tests := map[string]struct {
		frozen    string
		expect    string
		expectErr bool
	}{
		"Frozen": {
			frozen: "<frozen _bootstrap>",
			expect: "_bootstrap.py",
		},
		"Frozen subdir": {
			frozen: "<frozen importlib._bootstrap>",
			expect: "_bootstrap.py",
		},
		"Frozen broken": {
			frozen:    "<frozen _bootstrap",
			expectErr: true,
		},
		"Frozen empty": {
			frozen:    "<frozen >",
			expectErr: true,
		},
		"empty": {
			frozen: "",
			expect: "",
		},
	}

	for name, testcase := range tests {
		t.Run(name, func(t *testing.T) {
			out, err := frozenNameToFileName(testcase.frozen)

			if (err != nil) != testcase.expectErr {
				t.Fatalf("Unexpected error return")
			}

			if out != testcase.expect {
				t.Fatalf("'%s' does not match expected output '%s'", out, testcase.expect)
			}
		})
	}
}

func TestPythonRegexs(t *testing.T) {
	shouldMatch := map[*regexp.Regexp][]string{
		pythonRegex: {
			"python3.6", "./python3.6", "/foo/bar/python3.6", "./foo/bar/python3.6",
			"python3.7", "./python3.7", "/foo/bar/python3.7", "./foo/bar/python3.7"},
		libpythonRegex: {
			"libpython3.6", "./libpython3.6", "/foo/bar/libpython3.6",
			"./foo/bar/libpython3.6", "/foo/bar/libpython3.6.so.1",
			"/usr/lib64/libpython3.6m.so.1.0",
			"libpython3.7", "./libpython3.7", "/foo/bar/libpython3.7",
			"./foo/bar/libpython3.7", "/foo/bar/libpython3.7.so.1",
			"/foo/bar/libpython3.7m.so.1"},
	}

	for regex, strings := range shouldMatch {
		for _, s := range strings {
			assert.Truef(t, regex.MatchString(s),
				"%s should match: %v", regex.String(), s)
		}
	}

	shouldNotMatch := map[*regexp.Regexp][]string{
		pythonRegex: {
			"foopython3.6", "pyt hon3.6", "pyth/on3.6", "python",
			"foopython3.7", "pyt hon3.7", "pyth/on3.7", "python"},
		libpythonRegex: {
			"foolibpython3.6", "lib python3.6", "lib/python3.6",
			"foolibpython3.7", "lib python3.7", "lib/python3.7"},
	}

	for regex, strings := range shouldNotMatch {
		for _, s := range strings {
			assert.Falsef(t, regex.MatchString(s),
				"%v should not match: %v", regex.String(), s)
		}
	}
}

func TestPrologueHasFramePointer(t *testing.T) {
	// The byte sequences below are taken verbatim from the prologue of
	// _PyEval_EvalFrameDefault in the upstream python:3.15-rc CPython
	// builds for each architecture.
	tests := []struct {
		name    string
		machine elf.Machine
		code    []byte
		want    bool
	}{
		{
			name:    "x86-64 with endbr64 (3.15 default)",
			machine: elf.EM_X86_64,
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x55,             // push %rbp
				0x48, 0x89, 0xe5, // mov %rsp,%rbp
				0x41, 0x57, // push %r15
			},
			want: true,
		},
		{
			name:    "x86-64 without endbr64",
			machine: elf.EM_X86_64,
			code: []byte{
				0x55,             // push %rbp
				0x48, 0x89, 0xe5, // mov %rsp,%rbp
				0x41, 0x57, // push %r15
			},
			want: true,
		},
		{
			name:    "x86-64 -fomit-frame-pointer (no push rbp/mov rsp,rbp)",
			machine: elf.EM_X86_64,
			code: []byte{
				0xf3, 0x0f, 0x1e, 0xfa, // endbr64
				0x41, 0x57, // push %r15
				0x41, 0x56, // push %r14
				0x48, 0x83, 0xec, 0x18, // sub $0x18,%rsp
			},
			want: false,
		},
		{
			name:    "x86-64 too short",
			machine: elf.EM_X86_64,
			code:    []byte{0x55, 0x48},
			want:    false,
		},
		{
			name:    "arm64 with paciasp (3.15 default)",
			machine: elf.EM_AARCH64,
			code: []byte{
				0x3f, 0x23, 0x03, 0xd5, // paciasp
				0xfd, 0x7b, 0xba, 0xa9, // stp x29, x30, [sp, #-0x60]!
				0x03, 0x1f, 0x00, 0xf0, // adrp ...
				0x63, 0xcc, 0x44, 0xf9, // ldr ...
				0xfd, 0x03, 0x00, 0x91, // mov x29, sp
			},
			want: true,
		},
		{
			name:    "arm64 without paciasp",
			machine: elf.EM_AARCH64,
			code: []byte{
				0xfd, 0x7b, 0xba, 0xa9, // stp x29, x30, [sp, #-0x60]!
				0xfd, 0x03, 0x00, 0x91, // mov x29, sp
			},
			want: true,
		},
		{
			name:    "arm64 -fomit-frame-pointer (no mov x29, sp)",
			machine: elf.EM_AARCH64,
			code: []byte{
				0xff, 0x83, 0x00, 0xd1, // sub sp, sp, #0x20
				0xf3, 0x53, 0x01, 0xa9, // stp x19, x20, [sp, #0x10]
				0xf4, 0x4f, 0x02, 0xa9, // stp x20, x19, [sp, #0x20]
			},
			want: false,
		},
		{
			name:    "arm64 too short",
			machine: elf.EM_AARCH64,
			code:    []byte{0xfd, 0x03},
			want:    false,
		},
		{
			name:    "unsupported architecture",
			machine: elf.EM_RISCV,
			code:    []byte{0x55, 0x48, 0x89, 0xe5},
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := prologueHasFramePointer(tc.machine, tc.code)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestDetectFramePointersRealBinaries probes detectFramePointers against actual
// libpython binaries. Set LIBPYTHON_FP_TEST=<path>:<expect>[,<path>:<expect>...]
// to run, where <expect> is "true" or "false". Skipped otherwise so normal test
// runs do not depend on external files.
//
// Example:
//
//	LIBPYTHON_FP_TEST=/tmp/fp-test/libpython3.15.so:true,/tmp/fp-test/libpython3.13.so:true \
//	  go test -v -run TestDetectFramePointersRealBinaries ./interpreter/python
func TestDetectFramePointersRealBinaries(t *testing.T) {
	spec := os.Getenv("LIBPYTHON_FP_TEST")
	if spec == "" {
		t.Skip("LIBPYTHON_FP_TEST not set; skipping real-binary detection test")
	}
	for _, entry := range regexp.MustCompile(`,\s*`).Split(spec, -1) {
		parts := regexp.MustCompile(`:`).Split(entry, 2)
		require.Len(t, parts, 2, "entry %q must be path:bool", entry)
		path, expectStr := parts[0], parts[1]
		expect := expectStr == "true"

		t.Run(path, func(t *testing.T) {
			ef, err := pfelf.Open(path)
			require.NoError(t, err)
			defer ef.Close()
			got := detectFramePointers(ef)
			t.Logf("detectFramePointers(%s) = %v (expected %v)", path, got, expect)
			assert.Equal(t, expect, got)
		})
	}
}
