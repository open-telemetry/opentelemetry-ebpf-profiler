/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFifo(t *testing.T) {
	var integers []int
	integers = append(integers, 1, 2, 3, 4, 5)

	var integersShared []int
	integersShared = append(integersShared, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12)

	var retIntegers []int
	retIntegers = append(retIntegers, 3, 4, 5)

	var retIntegersShared []int
	retIntegersShared = append(retIntegersShared, 8, 9, 10, 11, 12)

	sharedFifo := &FifoRingBuffer[int]{}
	err := sharedFifo.InitFifo(5, t.Name())
	require.NoError(t, err)

	//nolint:lll
	tests := map[string]struct {
		// size defines the size of the fifo.
		size uint32
		// data will be written to and extracted from the fifo.
		data []int
		// returned reflects the data that is expected from the fifo
		// after writing to it.
		returned []int
		// the number of overwrites that occurred
		overwriteCount uint32
		// err indicates if an error is expected for this testcase.
		err bool
		// sharedFifo indicates if a shared fifo should be used.
		// If false, a new fifo is used, specific to the testcase.
		sharedFifo bool
		// parallel indicates if parallelism should be enabled for this testcase.
		parallel bool
	}{
		// This testcase simulates a fifo with an invalid size of 0.
		"Invalid size": {size: 0, err: true, parallel: true},
		// This testcase simulates a case where the numbers of elements
		// written to the fifo represents the size of the fifo.
		"Full Fifo": {size: 5, data: integers, returned: integers, overwriteCount: 0, parallel: true},
		// This testcase simulates a case where the number of elements
		// written to the fifo exceed the size of the fifo.
		"Fifo overflow": {size: 3, data: integers, returned: retIntegers, overwriteCount: 2, parallel: true},
		// This testcase simulates a case where only a few elements are
		// written to the fifo and don't exceed the size of the fifo.
		"Partial full": {size: 15, data: integers, returned: integers, overwriteCount: 0, parallel: true},

		// The following test cases share the same fifo

		// This testcase simulates a case where the numbers of elements
		// written to the fifo represents the size of the fifo.
		"Shared Full Fifo": {data: integers, returned: integers, overwriteCount: 0, sharedFifo: true},
		// This testcase simulates a case where the number of elements
		// written to the fifo exceed the size of the fifo.
		"Shared Fifo overflow": {data: integersShared, returned: retIntegersShared, overwriteCount: 7, sharedFifo: true},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		var fifo *FifoRingBuffer[int]

		t.Run(name, func(t *testing.T) {
			if testcase.parallel {
				t.Parallel()
			}

			if testcase.sharedFifo {
				fifo = sharedFifo
			} else {
				fifo = &FifoRingBuffer[int]{}
				err := fifo.InitFifo(testcase.size, t.Name())
				if testcase.err {
					require.Error(t, err)
					return
				}
				require.NoError(t, err)
			}

			empty := fifo.ReadAll()
			require.Empty(t, empty)

			for _, v := range testcase.data {
				fifo.Append(v)
			}

			data := fifo.ReadAll()
			for i := uint32(0); i < fifo.size; i++ {
				assert.Equalf(t, 0, fifo.data[i], "fifo not empty after ReadAll(), idx: %d", i)
			}
			assert.Equal(t, testcase.returned, data)
			assert.Equal(t, testcase.overwriteCount, fifo.GetOverwriteCount(), "overwrite count")
			assert.Zero(t, fifo.GetOverwriteCount(), "overwrite count not reset")
		})
	}
}

func TestFifo_isWritableWhenZeroed(t *testing.T) {
	fifo := &FifoRingBuffer[int]{}
	require.NoError(t, fifo.InitFifo(1, t.Name()))
	fifo.zeroFifo()
	assert.NotPanics(t, func() {
		fifo.Append(123)
	})
}
