//go:build nocgo && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pprof // import "go.opentelemetry.io/ebpf-profiler/interpreter/go/labels/integrationtests/pprof"

//go:noinline
func busyFunc() {
}
