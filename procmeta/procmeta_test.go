// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procmeta

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
)

// resourceWith builds a resource from string attributes.
func resourceWith(attrs map[string]string) *pcommon.Resource {
	r := pcommon.NewResource()
	for k, v := range attrs {
		r.Attributes().PutStr(k, v)
	}
	return &r
}

func TestMergeResources(t *testing.T) {
	tests := map[string]struct {
		base          *pcommon.Resource
		contributions []*pcommon.Resource
		expected      map[string]string
		expectNil     bool
	}{
		"no contributions": {
			contributions: nil,
			expectNil:     true,
		},
		"all nil": {
			contributions: []*pcommon.Resource{nil, nil},
			expectNil:     true,
		},
		"base only": {
			base:     resourceWith(map[string]string{"a": "1"}),
			expected: map[string]string{"a": "1"},
		},
		"contribution wins over base": {
			base: resourceWith(map[string]string{"a": "from-base", "c": "3"}),
			contributions: []*pcommon.Resource{
				resourceWith(map[string]string{"a": "contributed"}),
			},
			expected: map[string]string{"a": "contributed", "c": "3"},
		},
		"single contribution": {
			contributions: []*pcommon.Resource{nil, resourceWith(map[string]string{"a": "1"})},
			expected:      map[string]string{"a": "1"},
		},
		"disjoint keys": {
			contributions: []*pcommon.Resource{
				resourceWith(map[string]string{"a": "1"}),
				resourceWith(map[string]string{"b": "2"}),
			},
			expected: map[string]string{"a": "1", "b": "2"},
		},
		"later contribution wins on collision": {
			contributions: []*pcommon.Resource{
				resourceWith(map[string]string{"a": "first", "b": "2"}),
				resourceWith(map[string]string{"a": "second"}),
			},
			expected: map[string]string{"a": "second", "b": "2"},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			merged := MergeResources(test.base, test.contributions)
			if test.expectNil {
				require.Nil(t, merged)
				return
			}
			require.NotNil(t, merged)

			got := make(map[string]string, merged.Attributes().Len())
			merged.Attributes().Range(func(k string, v pcommon.Value) bool {
				got[k] = v.Str()
				return true
			})
			require.Equal(t, test.expected, got)
		})
	}
}

// TestMergeResourcesDoesNotModifyContributions verifies that merging leaves the
// inputs untouched: the process manager retains them across synchronizations and
// re-merges them, so a merge that mutated them would corrupt later merges.
func TestMergeResourcesDoesNotModifyContributions(t *testing.T) {
	first := resourceWith(map[string]string{"a": "first"})
	second := resourceWith(map[string]string{"a": "second"})

	merged := MergeResources(first, []*pcommon.Resource{second})
	require.NotNil(t, merged)

	v, ok := merged.Attributes().Get("a")
	require.True(t, ok)
	require.Equal(t, "second", v.Str())

	v, ok = first.Attributes().Get("a")
	require.True(t, ok)
	require.Equal(t, "first", v.Str())
	v, ok = second.Attributes().Get("a")
	require.True(t, ok)
	require.Equal(t, "second", v.Str())
}

// TestMergeResourcesSharesSingleContribution documents that a lone contribution
// is returned as-is rather than copied. Contributions are immutable, so sharing
// is safe and avoids an allocation on the common single-enricher path.
func TestMergeResourcesSharesSingleContribution(t *testing.T) {
	only := resourceWith(map[string]string{"a": "1"})
	require.Same(t, only, MergeResources(nil, []*pcommon.Resource{nil, only, nil}))
	// Likewise a base with no contribution to merge onto it.
	require.Same(t, only, MergeResources(only, nil))
}
