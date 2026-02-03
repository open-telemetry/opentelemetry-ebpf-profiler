// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"errors"
)

// List of public errors.
var (
	// ErrSymbolNotFound is returned when the requested symbol was not found.
	ErrSymbolNotFound = errors.New("symbol not found")
	// ErrNoSymbolHash is returned when the ELF has no symbol hash table (DT_GNU_HASH or DT_HASH).
	ErrNoSymbolHash = errors.New("symbol hash not present")
)

// SymbolValue represents the value associated with a symbol, e.g. either an
// offset or an absolute address
type SymbolValue uint64

// SymbolName represents the name of a symbol
type SymbolName string

// SymbolValueInvalid is the value returned by SymbolMap functions when symbol was not found.
const SymbolValueInvalid = SymbolValue(0)

// SymbolNameUnknown is the value returned by SymbolMap functions when address has no symbol info.
const SymbolNameUnknown = ""

// Symbol represents the name of a symbol
type Symbol struct {
	Name    SymbolName
	Address SymbolValue
	Size    uint64
}
