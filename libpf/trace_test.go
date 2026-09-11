// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewEbpfFrameHeaderMatchesNewEbpfFrame(t *testing.T) {
	header := NewEbpfFrameHeader(NativeFrame, FrameFlags(0x3), 2, 0x12345)
	frame := NewEbpfFrame(NativeFrame, FrameFlags(0x3), 2, 0x12345)

	assert.Equal(t, header, frame[0])
}

func newHashTestTrace() *Trace {
	trace := &Trace{}
	for i := range uint64(3) {
		trace.Frames.Append(&Frame{
			Type:            NativeFrame,
			AddressOrLineno: AddressOrLineno(i),
			Mapping: NewFrameMapping(FrameMappingData{
				File: NewFrameMappingFile(FrameMappingFileData{
					FileID: NewFileID(i, i),
				}),
			}),
		})
	}
	return trace
}

func TestTraceHash(t *testing.T) {
	tests := map[string]struct {
		trace  *Trace
		result TraceHash
	}{
		"empty trace": {
			trace:  &Trace{},
			result: NewTraceHash(0x6c62272e07bb0142, 0x62b821756295c58d)},
		"native trace": {
			trace:  newHashTestTrace(),
			result: NewTraceHash(0x21c6fe4c62868856, 0xcf510596eab68dc8)},
	}

	for name, testcase := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, testcase.result, testcase.trace.APMHash())
			// The memoized result must match the first computation.
			assert.Equal(t, testcase.result, testcase.trace.APMHash())
		})
	}
}
