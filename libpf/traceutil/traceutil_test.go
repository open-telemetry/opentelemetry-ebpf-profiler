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
)

func TestLibpfEBPFFrameMarkerEquality(t *testing.T) {
	// This test ensures that the frame markers used in eBPF are the same used in libpf.
	arr0 := []libpf.FrameType{libpf.NativeFrame, libpf.PythonFrame, libpf.PHPFrame}
	arr1 := []int{support.FrameMarkerNative, support.FrameMarkerPython, support.FrameMarkerPHP}

	for i := 0; i < len(arr0); i++ {
		if int(arr0[i]) != arr1[i] {
			t.Fatalf("Inequality at index %d : %d != %d", i, arr0[i], arr1[i])
		}
	}
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
			hash := HashTrace(testcase.trace)
			if hash != testcase.result {
				t.Fatalf("Expected 0x%x got 0x%x", testcase.result, hash)
			}
		})
	}
}
