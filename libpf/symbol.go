// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"errors"
)

// ErrSymbolNotFound is returned when the requested symbol was not found.
var ErrSymbolNotFound = errors.New("symbol not found")

// SymbolValue represents the value associated with a symbol, e.g. either an
// offset or an absolute address
type SymbolValue uint64

// SymbolName represents the name of a symbol
type SymbolName string

// SymbolValueInvalid is the value returned by SymbolMap functions when symbol was not found.
const SymbolValueInvalid = SymbolValue(0)

// SymbolNameUnknown is the value returned by SymbolMap functions when address has no symbol info.
const SymbolNameUnknown = ""

// SymbolType represents the ELF symbol type (STT_FUNC, STT_OBJECT, etc.)
type SymbolType uint8

const (
	SymbolTypeNone    SymbolType = 0  // STT_NOTYPE
	SymbolTypeObject  SymbolType = 1  // STT_OBJECT
	SymbolTypeFunc    SymbolType = 2  // STT_FUNC
	SymbolTypeSection SymbolType = 3  // STT_SECTION
	SymbolTypeFile    SymbolType = 4  // STT_FILE
	SymbolTypeTLS     SymbolType = 6  // STT_TLS
	SymbolTypeIFunc   SymbolType = 10 // STT_GNU_IFUNC
)

// IsFunction returns true if the symbol type represents executable code.
func (t SymbolType) IsFunction() bool {
	return t == SymbolTypeFunc || t == SymbolTypeIFunc
}

// Symbol represents the name of a symbol
type Symbol struct {
	Name    SymbolName
	Address SymbolValue
	Size    uint64
	Type    SymbolType
}
