// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"hash/crc32"
	"unique"
)

// String is an interned string. This is a wrapper for unique.Handle[string],
// but provides String() to be usable as printf, and also treats the default
// initializer as the empty string.
type String struct {
	value unique.Handle[string]
}

var NullString = String{unique.Handle[string]{}}

func Intern(str string) String {
	if str == "" {
		return NullString
	}
	return String{unique.Make(str)}
}

func (s String) String() string {
	if s == NullString {
		return ""
	}
	return s.value.Value()
}

// StringHashCRC32 computes a 32-bit hash of a String using CRC32 with IEEE polynomial.
func StringHashCRC32(s String) uint32 {
	return crc32.ChecksumIEEE([]byte(s.String()))
}
