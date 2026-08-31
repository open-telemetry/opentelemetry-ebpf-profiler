//go:build amd64

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package luajit // import "go.opentelemetry.io/ebpf-profiler/interpreter/luajit"

import "go.opentelemetry.io/ebpf-profiler/support"

const (
	cframeSize    int32 = support.LJCframeSpaceX86
	cframeSizeJIT int32 = cframeSize + 16
)
