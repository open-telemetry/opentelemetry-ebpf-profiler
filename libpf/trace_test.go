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

func TestTraceHashCustomLabels(t *testing.T) {
	labels := map[String]String{
		Intern("first"):  Intern("one"),
		Intern("second"): Intern("two"),
	}
	trace := newHashTestTrace()
	trace.CustomLabels = labels
	hash := trace.Hash()
	apmHash := newHashTestTrace().APMHash()
	assert.Equal(t, apmHash, trace.APMHash())

	reordered := make(map[String]String)
	reordered[Intern("second")] = Intern("two")
	reordered[Intern("first")] = Intern("one")

	tests := map[string]struct {
		labels map[String]String
		equal  bool
	}{
		"same labels in reverse order": {labels: reordered, equal: true},
		"different value": {labels: map[String]String{
			Intern("first"):  Intern("different"),
			Intern("second"): Intern("two"),
		}},
		"different key": {labels: map[String]String{
			Intern("other"):  Intern("one"),
			Intern("second"): Intern("two"),
		}},
		"swapped values": {labels: map[String]String{
			Intern("first"):  Intern("two"),
			Intern("second"): Intern("one"),
		}},
		"missing label": {labels: map[String]String{
			Intern("first"): Intern("one"),
		}},
		"nil labels":   {},
		"empty labels": {labels: map[String]String{}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			other := newHashTestTrace()
			other.CustomLabels = test.labels
			otherHash := other.Hash()
			assert.Equal(t, apmHash, other.APMHash())
			if test.equal {
				assert.Equal(t, hash, otherHash)
			} else {
				assert.NotEqual(t, hash, otherHash)
			}
			assert.Equal(t, otherHash, other.Hash())
		})
	}

	empty := newHashTestTrace()
	empty.CustomLabels = map[String]String{}
	assert.Equal(t, newHashTestTrace().Hash(), empty.Hash())

	emptyPair := newHashTestTrace()
	emptyPair.CustomLabels = map[String]String{Intern(""): Intern("")}
	assert.NotEqual(t, empty.Hash(), emptyPair.Hash())

	differentFrames := &Trace{CustomLabels: labels}
	assert.NotEqual(t, hash, differentFrames.Hash())

	trace.CustomLabels[Intern("first")] = Intern("changed")
	trace.Frames = nil
	assert.Equal(t, hash, trace.Hash())
}
