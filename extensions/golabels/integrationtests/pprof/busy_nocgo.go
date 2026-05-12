//go:build nocgo && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package pprof // import "go.opentelemetry.io/ebpf-profiler/extensions/golabels/integrationtests/pprof"

//go:noinline
func busyFunc() {
}
