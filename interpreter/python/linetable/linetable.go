// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package linetable maps CPython bytecode offsets to source lines.
package linetable // import "go.opentelemetry.io/ebpf-profiler/interpreter/python/linetable"

import "go.opentelemetry.io/ebpf-profiler/interpreter/python/internal/linetable"

var (
	// ErrInvalidTable indicates a malformed table or an offset beyond its ranges.
	ErrInvalidTable = linetable.ErrInvalidTable

	// ErrNoLocation indicates that CPython marked the range as having no source line.
	ErrNoLocation = linetable.ErrNoLocation
)

// Lookup returns the source line at byteOffset for the given CPython 3 minor
// version. Pass co_firstlineno as firstLine and the contents of co_lnotab
// (before 3.10) or co_linetable (3.10 and later) as table.
// Lookup validates the entries it reads through the requested offset.
func Lookup(minor uint8, table []byte, firstLine, byteOffset uint32) (uint32, error) {
	return linetable.Lookup(minor, table, firstLine, byteOffset)
}
