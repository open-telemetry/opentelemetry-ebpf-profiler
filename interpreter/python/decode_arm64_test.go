//go:build arm64

/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package python

import (
	"testing"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/stretchr/testify/assert"
)

func TestAnalyzeArm64Stubs(t *testing.T) {
	val := decodeStubArgumentWrapper(
		[]byte{
			0x40, 0x0a, 0x00, 0x90, 0x01, 0xd4, 0x43, 0xf9,
			0x22, 0x60, 0x17, 0x91, 0x40, 0x00, 0x40, 0xf9,
			0xa2, 0xff, 0xff, 0x17},
		0, 0, 0)
	assert.Equal(t, libpf.SymbolValue(1496), val, "PyEval_ReleaseLock stub test")

	val = decodeStubArgumentWrapper(
		[]byte{
			0x80, 0x12, 0x00, 0xb0, 0x02, 0xd4, 0x43, 0xf9,
			0x41, 0xf4, 0x42, 0xf9, 0x61, 0x00, 0x00, 0xb4,
			0x40, 0xc0, 0x17, 0x91, 0xad, 0xe4, 0xfe, 0x17},
		0, 0, 0)
	assert.Equal(t, libpf.SymbolValue(1520), val, "PyGILState_GetThisThreadState test")
}
