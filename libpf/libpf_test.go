// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTraceType(t *testing.T) {
	tests := []struct {
		ty     FrameType
		isErr  bool
		interp InterpreterType
		str    string
	}{
		{
			ty:     AbortFrame,
			isErr:  true,
			interp: UnknownInterp,
			str:    "abort-marker",
		},
		{
			ty:     PythonFrame,
			isErr:  false,
			interp: Python,
			str:    "cpython",
		},
		{
			ty:     NativeFrame.Error(),
			isErr:  true,
			interp: Native,
			str:    "native-error",
		},
	}

	for _, test := range tests {
		assert.Equal(t, test.isErr, test.ty.IsError())
		assert.Equal(t, test.interp, test.ty.Interpreter())
		assert.Equal(t, test.str, test.ty.String())
	}
}

func TestUnixTime64_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		time UnixTime64
		want []byte
	}{
		{
			name: "zero",
			time: UnixTime64(0),
			want: []byte(strconv.Itoa(0)),
		},
		{
			name: "non-zero, seconds since the epoch",
			time: UnixTime64(1710349106),
			want: []byte(strconv.Itoa(1710349106)),
		},
		{
			name: "non-zero, nanoseconds since the epoch",
			time: UnixTime64(1710349106864964685),
			want: []byte(fmt.Sprintf("%q", "2024-03-13T16:58:26.864964685Z")),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			b, err := test.time.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, test.want, b)
		})
	}
}
