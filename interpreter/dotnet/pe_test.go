// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"bytes"
	"encoding/binary"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// nestedClassTable encodes rows as an ECMA-335 II.22.32 NestedClass table using
// 2-byte TypeDef indexes. Each pair is (NestedClass, EnclosingClass).
func nestedClassTable(rows ...[2]uint16) io.ReadSeeker {
	var buf bytes.Buffer
	for _, row := range rows {
		_ = binary.Write(&buf, binary.LittleEndian, row[0])
		_ = binary.Write(&buf, binary.LittleEndian, row[1])
	}
	return bytes.NewReader(buf.Bytes())
}

// TestParseNestedClass covers the validation of the ECMA-335 II.22.32
// NestedClass table, which is parsed from the profiled process' PE file and is
// therefore untrusted. Rows that violate the II.22 ordering rule ("the
// definition of an enclosing class shall precede the definition of all classes
// it encloses") are rejected, which keeps the enclosing-class chains walked by
// resolveMethodName acyclic by construction.
func TestParseNestedClass(t *testing.T) {
	const numTypeDefs = 4

	testCases := map[string]struct {
		rows [][2]uint16
		// enclosing is the expected enclosingClass of each typeSpec on success.
		enclosing []uint32
		err       string
	}{
		"valid nesting chain": {
			// TypeDef 1 encloses 2, which encloses 3.
			rows:      [][2]uint16{{2, 1}, {3, 2}},
			enclosing: []uint32{0, 1, 2, 0},
		},
		"self reference": {
			rows: [][2]uint16{{2, 2}},
			err:  "enclosing class 2 does not precede nested class 2",
		},
		"enclosing class defined after nested class": {
			// A single row that would make resolveMethodName walk forward, and
			// in combination with {2, 3} would form a cycle.
			rows: [][2]uint16{{2, 3}},
			err:  "enclosing class 3 does not precede nested class 2",
		},
		"mutual cycle": {
			// The first row is already invalid; the walk never sees the pair.
			rows: [][2]uint16{{2, 3}, {3, 2}},
			err:  "enclosing class 3 does not precede nested class 2",
		},
		"index out of range": {
			rows: [][2]uint16{{numTypeDefs + 1, 1}},
			err:  "indexes (5/1) vs. 4 typedefs",
		},
		"zero index": {
			rows: [][2]uint16{{2, 0}},
			err:  "indexes (2/0) vs. 4 typedefs",
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			pp := &peParser{
				info:         &peInfo{typeSpecs: make([]peTypeSpec, numTypeDefs)},
				dotnetTables: nestedClassTable(test.rows...),
			}
			pp.indexSizes[indexTypeDef] = 2
			pp.tableRows[tableNestedClass] = uint32(len(test.rows))

			pp.parseNestedClass()

			if test.err != "" {
				require.Error(t, pp.err)
				assert.Contains(t, pp.err.Error(), test.err)
				return
			}
			require.NoError(t, pp.err)

			enclosing := make([]uint32, len(pp.info.typeSpecs))
			for i, spec := range pp.info.typeSpecs {
				enclosing[i] = spec.enclosingClass
			}
			assert.Equal(t, test.enclosing, enclosing)
		})
	}
}

// TestResolveMethodNameNesting checks that resolveMethodName walks a nesting
// chain that satisfies the invariant enforced by parseNestedClass. The chain is
// deeper than any realistic source-level nesting to show that the walk is
// bounded by the number of TypeDefs rather than by the data.
func TestResolveMethodNameNesting(t *testing.T) {
	const depth = 64

	// typeSpecs[depth-1] is the innermost type and owns method index 1; each
	// type is enclosed by the one before it, so every enclosingClass is
	// strictly lower than its own index, as parseNestedClass requires.
	typeSpecs := make([]peTypeSpec, depth)
	for i := range typeSpecs {
		if i > 0 {
			typeSpecs[i].enclosingClass = uint32(i)
		}
		// methodIdx must be ascending for the binary search in
		// resolveMethodName. Only the innermost type owns method index 1.
		if i == depth-1 {
			typeSpecs[i].methodIdx = 1
		}
	}

	pi := &peInfo{
		typeSpecs:   typeSpecs,
		methodSpecs: []peMethodSpec{{}},
	}

	// All string offsets are zero, so lookupString returns libpf.NullString
	// without touching the strings cache or remote memory, which makes the
	// zero-value RemoteMemory{} safe here.
	res := pi.resolveMethodName(1, remotememory.RemoteMemory{}, 0)

	// depth type names joined by "/", then ".<method name>".
	assert.Equal(t, depth-1, strings.Count(res.String(), "/"))
}
