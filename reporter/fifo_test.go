/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
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

	sharedFifo := &fifoRingBuffer[int]{}
	if err := sharedFifo.initFifo(5, t.Name()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// nolint:lll
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
		var fifo *fifoRingBuffer[int]

		t.Run(name, func(t *testing.T) {
			if testcase.parallel {
				t.Parallel()
			}

			if testcase.sharedFifo {
				fifo = sharedFifo
			} else {
				fifo = &fifoRingBuffer[int]{}
				if err := fifo.initFifo(testcase.size, t.Name()); err != nil {
					if testcase.err {
						// We expected an error and received it.
						// So we can continue.
						return
					}
					t.Fatalf("unexpected error: %v", err)
				}
			}

			empty := fifo.readAll()
			if len(empty) != 0 {
				t.Fatalf("Nothing was added to fifo but fifo returned %d elements", len(empty))
			}

			for _, v := range testcase.data {
				fifo.append(v)
			}

			data := fifo.readAll()
			for i := uint32(0); i < fifo.size; i++ {
				if fifo.data[i] != 0 {
					t.Errorf("fifo not empty after readAll(), idx: %d", i)
				}
			}

			if diff := cmp.Diff(testcase.returned, data); diff != "" {
				t.Errorf("returned data (%d) mismatch (-want +got):\n%s", len(data), diff)
			}

			overwriteCount := fifo.getOverwriteCount()
			if overwriteCount != testcase.overwriteCount {
				t.Fatalf("expected an overwrite count %d but got %d", testcase.overwriteCount,
					overwriteCount)
			}
			overwriteCount = fifo.getOverwriteCount()
			if overwriteCount != 0 {
				t.Fatalf(
					"after retrieving the overwriteCount, it should be reset to 0 but got %d",
					overwriteCount)
			}
		})
	}
}

func TestFifo_isWritableWhenZeroed(t *testing.T) {
	fifo := &fifoRingBuffer[int]{}
	assert.Nil(t, fifo.initFifo(1, t.Name()))
	fifo.zeroFifo()
	assert.NotPanics(t, func() {
		fifo.append(123)
	})
}
