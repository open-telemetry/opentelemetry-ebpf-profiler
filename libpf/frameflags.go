// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"go.opentelemetry.io/ebpf-profiler/support"
)

// FrameFlags defines the flags of an ebpf frame.
type FrameFlags uint8

func (ff FrameFlags) Error() bool {
	return ff&support.FrameFlagError != 0
}

func (ff FrameFlags) ReturnAddress() bool {
	return ff&support.FrameFlagReturnAddress != 0
}

func (ff FrameFlags) PIDSpecific() bool {
	return ff&support.FrameFlagPidSpecific != 0
}
