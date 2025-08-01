// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package traceutil

import (
	"testing"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/support"

	"github.com/stretchr/testify/assert"
)

//nolint:testifylint
func TestLibpfEBPFFrameMarkerEquality(t *testing.T) {
	assert.Equal(t, int(libpf.NativeFrame), support.FrameMarkerNative)
	assert.Equal(t, int(libpf.PythonFrame), support.FrameMarkerPython)
	assert.Equal(t, int(libpf.PHPFrame), support.FrameMarkerPHP)
}

func newPythonTrace() *libpf.Trace {
	trace := &libpf.Trace{}
	trace.AppendFrame(libpf.NativeFrame, libpf.NewFileID(0, 0), 0)
	trace.AppendFrame(libpf.NativeFrame, libpf.NewFileID(1, 1), 1)
	trace.AppendFrame(libpf.NativeFrame, libpf.NewFileID(2, 2), 2)
	return trace
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
			trace:  newPythonTrace(),
			result: libpf.NewTraceHash(0x21c6fe4c62868856, 0xcf510596eab68dc8)},
	}

	for name, testcase := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.result, HashTrace(testcase.trace))
		})
	}
}
