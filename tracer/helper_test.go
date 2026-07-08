package tracer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadCPURange(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []int
	}{
		"mixed": {
			input:    "0,3-6,8-11",
			expected: []int{0, 3, 4, 5, 6, 8, 9, 10, 11},
		},
		"all": {
			input:    "0-7",
			expected: []int{0, 1, 2, 3, 4, 5, 6, 7},
		},
		"empty": {
			input:    "",
			expected: []int{},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := ReadCPURange(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}

func TestIntersectCPURanges(t *testing.T) {
	tests := map[string]struct {
		online   []int
		enabled  []int
		expected []int
		wantErr  bool
	}{
		"all": {
			online:   []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			enabled:  []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			expected: []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			wantErr:  false,
		},
		"partial intersection": {
			online:   []int{0, 2, 4, 6, 8},
			enabled:  []int{0, 1, 2, 3, 4},
			expected: []int{0, 2, 4},
			wantErr:  false,
		},
		"empty intersection": {
			online:   []int{0, 2, 4, 6, 8},
			enabled:  []int{1, 3, 5, 7, 9},
			expected: nil,
			wantErr:  true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := intersectCPURanges(tc.online, tc.enabled)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.expected, got)
			}
		})
	}
}
