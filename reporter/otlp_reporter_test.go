/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDedupSlice(t *testing.T) {
	tests := map[string]struct {
		values   []uint64
		out      []uint64
		outCount []int64
	}{
		"single timestamp": {
			values:   []uint64{42},
			out:      []uint64{42},
			outCount: []int64{1},
		},
		"duplicate timestamps": {
			values:   []uint64{42, 42, 42},
			out:      []uint64{42},
			outCount: []int64{3},
		},
		"mixed timestamps": {
			values:   []uint64{42, 73, 42, 37, 42, 11},
			out:      []uint64{11, 37, 42, 73},
			outCount: []int64{1, 1, 3, 1},
		},
	}

	for name, test := range tests {
		name := name
		test := test
		t.Run(name, func(t *testing.T) {
			newVal, newCount := dedupSlice(test.values)
			assert.Equal(t, test.out, newVal)
			assert.Equal(t, test.outCount, newCount)
		})
	}
}
