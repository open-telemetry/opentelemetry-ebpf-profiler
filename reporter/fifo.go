/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package reporter

import (
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

// FifoRingBuffer implements a first-in-first-out ring buffer that is safe for concurrent access.
type FifoRingBuffer[T any] struct { //nolint:gocritic
	sync.Mutex

	// data holds the actual data.
	data []T

	// emptyT is variable of type T used for nullifying entries in data[].
	emptyT T

	// name holds a string to uniquely identify the ring buffer in log messages.
	name string

	// size is the maximum number of entries in the ring buffer.
	size uint32

	// readPos holds the position of the first element to be read in the data array.
	readPos uint32

	// writePos holds the position where the next element should be
	// placed in the data array.
	writePos uint32

	// count holds a count of how many entries are in the array.
	count uint32

	// overwriteCount holds a count of the number of overwritten entries since the last metric
	// report interval.
	overwriteCount uint32
}

func (q *FifoRingBuffer[T]) InitFifo(size uint32, name string) error {
	if size == 0 {
		return fmt.Errorf("unsupported size of fifo: %d", size)
	}
	q.Lock()
	defer q.Unlock()
	q.size = size
	q.data = make([]T, size)
	q.readPos = 0
	q.writePos = 0
	q.count = 0
	q.overwriteCount = 0
	q.name = name
	return nil
}

// zeroFifo re-initializes the ring buffer and clears the data array, making previously
// stored elements available for GC.
func (q *FifoRingBuffer[T]) zeroFifo() {
	if err := q.InitFifo(q.size, q.name); err != nil {
		// Should never happen
		panic(err)
	}
}

// Append adds element v to the FifoRingBuffer. it overwrites existing elements if there is no
// space left.
func (q *FifoRingBuffer[T]) Append(v T) {
	q.Lock()
	defer q.Unlock()

	q.data[q.writePos] = v
	q.writePos++

	if q.writePos == q.size {
		q.writePos = 0
	}

	if q.count < q.size {
		q.count++
		if q.count == q.size {
			log.Warnf("About to start overwriting elements in buffer for %s",
				q.name)
		}
	} else {
		q.overwriteCount++
		q.readPos = q.writePos
	}
}

// ReadAll returns all elements from the FifoRingBuffer.
func (q *FifoRingBuffer[T]) ReadAll() []T {
	q.Lock()
	defer q.Unlock()

	data := make([]T, q.count)
	readPos := q.readPos

	for i := uint32(0); i < q.count; i++ {
		pos := (i + readPos) % q.size
		data[i] = q.data[pos]
		// Allow for element to be GCed
		q.data[pos] = q.emptyT
	}

	q.readPos = q.writePos
	q.count = 0

	return data
}

func (q *FifoRingBuffer[T]) GetOverwriteCount() uint32 {
	q.Lock()
	defer q.Unlock()

	count := q.overwriteCount
	q.overwriteCount = 0
	return count
}
