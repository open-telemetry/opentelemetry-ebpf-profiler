// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stringutil // import "go.opentelemetry.io/ebpf-profiler/stringutil"

import (
	"bytes"
	"strings"
	"unicode/utf8"
)

var asciiSpace = [256]uint8{'\t': 1, '\n': 1, '\v': 1, '\f': 1, '\r': 1, ' ': 1}

// CString returns the prefix of buf up to (but not including) the first NUL
// byte, or all of buf if no NUL is present. Suitable for fixed-size buffers
// populated from eBPF.
func CString(buf []byte) []byte {
	if before, _, ok := bytes.Cut(buf, []byte{0}); ok {
		return before
	}
	return buf
}

// ValidUTF8Prefix returns the longest valid-UTF8 prefix of buf. A fixed-width
// eBPF buffer can clip a multi-byte rune in half, so this salvages the valid
// part rather than rejecting the whole value. ok is false only when nothing of
// buf is valid UTF-8 (a non-empty buf whose salvage is empty). The returned
// slice aliases buf.
func ValidUTF8Prefix(buf []byte) (prefix []byte, ok bool) {
	if utf8.Valid(buf) {
		return buf, true
	}
	pos := 0
	for pos < len(buf) {
		r, size := utf8.DecodeRune(buf[pos:])
		if r == utf8.RuneError && size == 1 {
			break
		}
		pos += size
	}
	return buf[:pos], pos > 0
}

// FieldsN splits the string s around each instance of one or more consecutive ASCII space
// characters, filling f with substrings of s.
// If s contains more fields than len(f), the last element of f is set to the
// unparsed remainder of s starting with the first non-space character.
// f will stay untouched if s is empty or contains only white space.
// Returns 0 if f is empty.
//
// Apart from the mentioned differences, FieldsN is like an allocation-free strings.Fields.
func FieldsN(s string, f []string) int {
	n := len(f)
	if n == 0 {
		return 0
	}
	si := 0
	for i := 0; i < n-1; i++ {
		// Find the start of the next field.
		for si < len(s) && asciiSpace[s[si]] != 0 {
			si++
		}
		fieldStart := si

		// Find the end of the field.
		for si < len(s) && asciiSpace[s[si]] == 0 {
			si++
		}
		if fieldStart >= si {
			return i
		}

		f[i] = s[fieldStart:si]
	}

	// Find the start of the next field.
	for si < len(s) && asciiSpace[s[si]] != 0 {
		si++
	}

	// Put the remainder of s as last element of f.
	if si < len(s) {
		f[n-1] = s[si:]
		return n
	}

	return n - 1
}

// SplitN splits the string around each instance of sep, filling f with substrings of s.
// If s contains more fields than len(f), the last element of f is set to the
// unparsed remainder of s.
// Returns 0 if f is empty.
//
// Apart from the mentioned differences, SplitN is like an allocation-free strings.SplitN.
func SplitN(s, sep string, f []string) int {
	n := len(f)
	if n == 0 {
		return 0
	}
	i := 0
	for ; i < n-1 && s != ""; i++ {
		fieldEnd := strings.Index(s, sep)
		if fieldEnd < 0 {
			f[i] = s
			return i + 1
		}
		f[i] = s[:fieldEnd]
		s = s[fieldEnd+len(sep):]
	}

	// Put the remainder of s as last element of f.
	f[i] = s
	return i + 1
}
