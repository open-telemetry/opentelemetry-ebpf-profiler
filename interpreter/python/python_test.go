// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package python

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
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

// TestDecodePyVersionHex verifies the PY_VERSION_HEX bit-decoding against
// real CPython constants (the value stored in the Py_Version symbol). The
// layout is (major<<24)|(minor<<16)|(micro<<8)|(releaselevel<<4)|serial, so the
// low byte (release/serial) must not leak into major/minor/patch.
func TestDecodePyVersionHex(t *testing.T) {
	tests := map[string]struct {
		hex                             uint32
		wantMajor, wantMinor, wantPatch uint8
	}{
		// 0xMMmmppRS — RS = releaselevel(4b)+serial(4b); 0xF0 = final release.
		"3.8.0 final":  {0x030800F0, 3, 8, 0},
		"3.11.4 final": {0x030B04F0, 3, 11, 4},
		"3.12.7 final": {0x030C07F0, 3, 12, 7},
		"3.11.9 final": {0x030B09F0, 3, 11, 9},
		// Pre-releases still carry the correct micro; only the low byte differs.
		"3.14.0a1": {0x030E00A1, 3, 14, 0},
		// Two-digit micro must survive the mask.
		"3.9.19 final": {0x030913F0, 3, 9, 19},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			major, minor, patch := decodePyVersionHex(tt.hex)
			assert.Equal(t, tt.wantMajor, major)
			assert.Equal(t, tt.wantMinor, minor)
			assert.Equal(t, tt.wantPatch, patch)
		})
	}
}
