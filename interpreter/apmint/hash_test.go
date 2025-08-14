// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package apmint // import "go.opentelemetry.io/ebpf-profiler/interpreter/apmint"

import (
	"testing"
	"unique"

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
	trace.Frames.Append(&libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 0,
		MappingFile:     unique.Make(libpf.FrameMappingFileData{FileID: libpf.NewFileID(0, 0)}),
	})
	trace.Frames.Append(&libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 1,
		MappingFile:     unique.Make(libpf.FrameMappingFileData{FileID: libpf.NewFileID(1, 1)}),
	})
	trace.Frames.Append(&libpf.Frame{
		Type:            libpf.NativeFrame,
		AddressOrLineno: 2,
		MappingFile:     unique.Make(libpf.FrameMappingFileData{FileID: libpf.NewFileID(2, 2)}),
	})
	return trace
}

func TestHashTrace(t *testing.T) {
	tests := map[string]struct {
		trace  *libpf.Trace
		result [16]byte
	}{
		"empty trace": {
			trace: &libpf.Trace{},
			result: [16]uint8{0x6c, 0x62, 0x27, 0x2e, 0x7, 0xbb, 0x1, 0x42,
				0x62, 0xb8, 0x21, 0x75, 0x62, 0x95, 0xc5, 0x8d},
		},
		"python trace": {
			trace: newPythonTrace(),
			result: [16]byte{0x21, 0xc6, 0xfe, 0x4c, 0x62, 0x86, 0x88, 0x56,
				0xcf, 0x51, 0x5, 0x96, 0xea, 0xb6, 0x8d, 0xc8},
		},
	}

	for name, testcase := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.result, hashTrace(testcase.trace))
		})
	}
}
