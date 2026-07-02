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
