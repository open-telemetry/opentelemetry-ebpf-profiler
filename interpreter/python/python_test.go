// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"bytes"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

func TestGetCodeObjectSizeLimit(t *testing.T) {
	rm := remotememory.RemoteMemory{ReaderAt: bytes.NewReader(make([]byte, 4096))}
	cases := []struct {
		name      string
		size      uint
		wantSizeE bool
	}{
		{"oversized 1GiB", 1 << 30, true},
		{"zero", 0, true},
		{"just over cap", maxCodeObjectSize + 1, true},
		{"at cap", maxCodeObjectSize, false},
		{"nominal", 224, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &pythonData{}
			d.vmStructs.PyCodeObject.Sizeof = tc.size
			p := &pythonInstance{d: d, rm: rm}

			_, err := p.getCodeObject(libpf.Address(0x1234), 0)
			gotSizeErr := err != nil && strings.Contains(err.Error(), "unexpected PyCodeObject size")
			assert.Equal(t, tc.wantSizeE, gotSizeErr, "err: %v", err)
		})
	}
}

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
