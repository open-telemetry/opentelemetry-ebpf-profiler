/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package libpf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFrameTypeFromString(t *testing.T) {
	// Simple check whether all FrameType values can be converted to string and back.
	for _, ft := range []FrameType{
		unknownFrame, PHPFrame, PythonFrame, NativeFrame, KernelFrame, HotSpotFrame, RubyFrame,
		PerlFrame, V8Frame, DotnetFrame, AbortFrame} {
		name := ft.String()
		result := FrameTypeFromString(name)
		require.Equal(t, ft, result)
	}
}
