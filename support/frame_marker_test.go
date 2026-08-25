// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support_test

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
