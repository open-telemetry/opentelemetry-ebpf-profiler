//go:build arm64 && debugtracer

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package support

import (
	_ "embed"
)

//go:embed ebpf/tracer.ebpf.debug.arm64
var debugTracerData []byte
