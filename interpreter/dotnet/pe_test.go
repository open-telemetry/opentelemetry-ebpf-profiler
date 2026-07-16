// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package dotnet

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"go.opentelemetry.io/ebpf-profiler/remotememory"
)

// TestResolveMethodNameCyclicNestedClass ensures that cyclic enclosing-class
// chains (from untrusted ECMA-335 II.22.32 NestedClass metadata) are bounded by
// resolveMethodName instead of spinning forever with unbounded string growth.
// The call is run in a goroutine with a timeout so a regression fails fast
// rather than hanging the whole test binary.
func TestResolveMethodNameCyclicNestedClass(t *testing.T) {
	testCases := map[string]struct {
		typeSpecs []peTypeSpec
	}{
		"self-cycle": {
			// A type whose enclosing class is itself.
			typeSpecs: []peTypeSpec{
				{enclosingClass: 1},
			},
		},
		"mutual-cycle": {
			// Two types that enclose each other.
			typeSpecs: []peTypeSpec{
				{enclosingClass: 2},
				{enclosingClass: 1},
			},
		},
	}

	for name, test := range testCases {
		t.Run(name, func(t *testing.T) {
			pi := &peInfo{
				typeSpecs:   test.typeSpecs,
				methodSpecs: []peMethodSpec{{}},
			}

			done := make(chan string, 1)
			go func() {
				// String offsets are all zero here, so lookupString returns
				// libpf.NullString without touching the strings cache or remote
				// memory, making the zero-value RemoteMemory{} safe.
				done <- pi.resolveMethodName(1, remotememory.RemoteMemory{}, 0).String()
			}()

			select {
			case res := <-done:
				assert.Contains(t, res, "cyclic or too deep NestedClass metadata")
			case <-time.After(5 * time.Second):
				t.Fatal("resolveMethodName did not return within 5s; " +
					"cyclic NestedClass metadata likely caused an infinite loop")
			}
		})
	}
}

// TestResolveMethodNameDeepNesting ensures a legitimate, acyclic nesting chain
// (deeper than typical source but well within maxTypeNestingDepth) resolves
// normally without triggering the cycle sentinel.
func TestResolveMethodNameDeepNesting(t *testing.T) {
	const depth = 16
	typeSpecs := make([]peTypeSpec, depth)
	for i := range typeSpecs {
		// methodIdx must be sorted ascending for the binary search in
		// resolveMethodName. Give the innermost type methodIdx 1 and the rest
		// methodIdx 2 so that resolving method index 1 starts the walk at
		// typeSpecs[0].
		if i == 0 {
			typeSpecs[i].methodIdx = 1
		} else {
			typeSpecs[i].methodIdx = 2
		}
		// Link each type to the next as its enclosing class, leaving the last
		// one at the top of the chain (enclosingClass 0).
		if i < depth-1 {
			typeSpecs[i].enclosingClass = uint32(i + 2)
		}
	}

	pi := &peInfo{
		typeSpecs:   typeSpecs,
		methodSpecs: []peMethodSpec{{}},
	}

	res := pi.resolveMethodName(1, remotememory.RemoteMemory{}, 0).String()
	assert.NotContains(t, res, "cyclic or too deep NestedClass metadata")
}
