// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package linetable // import "go.opentelemetry.io/ebpf-profiler/interpreter/python/internal/linetable"

import "errors"

var (
	// ErrInvalidTable indicates a malformed table or an offset beyond its ranges.
	ErrInvalidTable = errors.New("invalid Python line table")

	// ErrNoLocation indicates that CPython marked the range as having no source line.
	ErrNoLocation = errors.New("bytecode has no Python source line")
)

// Lookup resolves an absolute source line with CPython's traceback semantics.
func Lookup(minor uint8, table []byte, firstLine, byteOffset uint32) (uint32, error) {
	line := int64(firstLine)
	var err error
	if minor >= 11 {
		// The location table stores lengths in two-byte code units.
		line, err = lookupLocation(table, line, byteOffset/2, false)
	} else {
		line, err = lookupLegacy(minor, table, line, byteOffset, false)
	}
	if err != nil {
		return 0, err
	}
	if line < 0 || line > int64(^uint32(0)) {
		return 0, ErrInvalidTable
	}
	return uint32(line), nil
}

// FunctionOffset returns the profiler's line offset relative to co_firstlineno.
// The position is the value captured by the Python unwinder.
func FunctionOffset(minor uint8, table []byte, position uint32) uint32 {
	if minor >= 11 {
		line, _ := lookupLocation(table, 0, position, true)
		return uint32(max(line, 0))
	}
	if minor == 10 && position == 0 {
		return 0
	}
	line, _ := lookupLegacy(minor, table, 0, position, true)
	return uint32(line)
}

// Before 3.10 a delta applies at the next boundary. In 3.10 it applies to
// the current range, with -128 marking a range without a source line.
func lookupLegacy(minor uint8, table []byte, line int64, offset uint32, profile bool) (int64, error) {
	if len(table)%2 != 0 {
		return 0, ErrInvalidTable
	}
	remaining := int64(offset)
	for i := 0; i < len(table); i += 2 {
		length := int64(table[i])
		delta := int8(table[i+1])
		if minor < 10 {
			if remaining < length {
				return line, nil
			}
			line += int64(delta)
		} else {
			if delta != -128 {
				line += int64(delta)
			}
			// For profiles, a zero delta extends the range and a missing
			// line advances the address. Lookup continues in both cases.
			if remaining < length && (!profile || (length != 0 && delta != 0 && delta != -128)) {
				if delta == -128 {
					return 0, ErrNoLocation
				}
				return line, nil
			}
		}
		remaining -= length
	}
	if minor < 10 {
		return line, nil
	}
	return 0, ErrInvalidTable
}

// lookupLocation walks the 3.11+ location table described in CPython's
// Objects/locations.md. Each entry starts with a byte with its high bit set.
func lookupLocation(table []byte, line int64, offset uint32, profile bool) (int64, error) {
	for len(table) > 0 {
		header := table[0]
		table = table[1:]
		if header&0x80 == 0 {
			return 0, ErrInvalidTable
		}

		length := uint32(header&7) + 1
		kind := (header >> 3) & 15
		switch {
		case kind <= 9:
			if len(table) < 1 || table[0]&0x80 != 0 {
				return 0, ErrInvalidTable
			}
			table = table[1:]
		case kind <= 12:
			if len(table) < 2 || (table[0]|table[1])&0x80 != 0 {
				return 0, ErrInvalidTable
			}
			line += int64(kind - 10)
			table = table[2:]
		case kind <= 14:
			value, n := readVarint(table)
			if n == 0 {
				return 0, ErrInvalidTable
			}
			delta := int64(value >> 1)
			if value&1 != 0 {
				delta = -delta
			}
			line += delta
			table = table[n:]
			if kind == 14 {
				// The long form also stores end-line and column information.
				for range 3 {
					_, n := readVarint(table)
					if n == 0 {
						return 0, ErrInvalidTable
					}
					table = table[n:]
				}
			}
		}
		if kind == 15 && profile {
			// Profiles historically reset the relative line at this entry.
			line = -1
		}
		if offset < length {
			if kind == 15 && !profile {
				return 0, ErrNoLocation
			}
			return line, nil
		}
		offset -= length
	}
	return 0, ErrInvalidTable
}

// readVarint reads six bits per byte. A zero length indicates invalid input.
func readVarint(table []byte) (uint32, int) {
	var value uint32
	for i, b := range table {
		if b&0x80 != 0 || (i == 5 && b > 3) {
			break
		}
		value |= uint32(b&63) << (6 * i)
		if b&64 == 0 {
			return value, i + 1
		}
	}
	return 0, 0
}
