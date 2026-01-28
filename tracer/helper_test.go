package tracer

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadCPURange(t *testing.T) {
	tests := map[string]struct {
		input    string
		expected []uint32
	}{
		"mixed": {
			input:    "0,3-6,8-11",
			expected: []uint32{0, 3, 4, 5, 6, 8, 9, 10, 11},
		},
		"all": {
			input:    "0-7",
			expected: []uint32{0, 1, 2, 3, 4, 5, 6, 7},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := readCPURange(tc.input)
			require.NoError(t, err)
			require.Equal(t, tc.expected, got)
		})
	}
}
