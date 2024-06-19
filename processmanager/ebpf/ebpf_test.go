//go:build !integration
// +build !integration

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package ebpf

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMapID(t *testing.T) {
	testCases := map[uint32]uint16{
		0:       8,
		1:       8,
		2:       8,
		0xFF:    8,  // 255
		0x100:   9,  // 256
		0x1FF:   9,  // 511
		0x200:   10, // 512
		0x3FF:   10, // 1023
		0x400:   11, // 1024
		0xFFFFF: 20, // 1048575 (2^20 - 1)
	}
	for numStackDeltas, expectedShift := range testCases {
		numStackDeltas := numStackDeltas
		expectedShift := expectedShift
		t.Run(fmt.Sprintf("deltas %d", numStackDeltas), func(t *testing.T) {
			shift, err := getMapID(numStackDeltas)
			require.NoError(t, err)
			assert.Equal(t, expectedShift, shift,
				fmt.Sprintf("wrong map name for %d deltas", numStackDeltas))
		})
	}

	_, err := getMapID(1 << 22)
	require.Error(t, err)
}
