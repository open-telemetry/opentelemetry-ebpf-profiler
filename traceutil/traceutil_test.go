/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package traceutil

import (
	"testing"

	"github.com/elastic/otel-profiling-agent/libpf"
	"github.com/elastic/otel-profiling-agent/support"

	"github.com/stretchr/testify/assert"
)

//nolint:testifylint
func TestLibpfEBPFFrameMarkerEquality(t *testing.T) {
	assert.Equal(t, int(libpf.NativeFrame), support.FrameMarkerNative)
	assert.Equal(t, int(libpf.PythonFrame), support.FrameMarkerPython)
	assert.Equal(t, int(libpf.PHPFrame), support.FrameMarkerPHP)
}

func TestHashTrace(t *testing.T) {
	tests := map[string]struct {
		trace  *libpf.Trace
		result libpf.TraceHash
	}{
		"empty trace": {
			trace:  &libpf.Trace{},
			result: libpf.NewTraceHash(0x6c62272e07bb0142, 0x62b821756295c58d)},
		"python trace": {
			trace: &libpf.Trace{
				Linenos: []libpf.AddressOrLineno{0, 1, 2},
				Files: []libpf.FileID{
					libpf.NewFileID(0, 0),
					libpf.NewFileID(1, 1),
					libpf.NewFileID(2, 2),
				},
				FrameTypes: []libpf.FrameType{
					libpf.NativeFrame,
					libpf.NativeFrame,
					libpf.NativeFrame,
				}},
			result: libpf.NewTraceHash(0x21c6fe4c62868856, 0xcf510596eab68dc8)},
	}

	for name, testcase := range tests {
		name := name
		testcase := testcase
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.result, HashTrace(testcase.trace))
		})
	}
}
