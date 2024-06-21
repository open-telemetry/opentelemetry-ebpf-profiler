/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package agentmetrics

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/assert"
)

func TestTimeDelta(t *testing.T) {
	tests := map[string]struct {
		now   unix.Timeval
		prev  unix.Timeval
		delta int64
	}{
		"1000ms": {now: unix.Timeval{
			Sec:  1,
			Usec: 0,
		}, prev: unix.Timeval{
			Sec:  0,
			Usec: 0,
		}, delta: 1000},
		"1ms": {now: unix.Timeval{
			Sec:  0,
			Usec: 1000,
		}, prev: unix.Timeval{
			Sec:  0,
			Usec: 0,
		}, delta: 1},
		"delta too small": {now: unix.Timeval{
			Sec:  0,
			Usec: 500,
		}, prev: unix.Timeval{
			Sec:  0,
			Usec: 0,
		}, delta: 0},
		"998 ms": {now: unix.Timeval{
			Sec:  1,
			Usec: 1000,
		}, prev: unix.Timeval{
			Sec:  0,
			Usec: 3000,
		}, delta: 998},
	}

	for name, tc := range tests {
		name := name
		tc := tc
		t.Run(name, func(t *testing.T) {
			delta := timeDelta(tc.now, tc.prev)
			assert.Equal(t, tc.delta, delta)
		})
	}
}
