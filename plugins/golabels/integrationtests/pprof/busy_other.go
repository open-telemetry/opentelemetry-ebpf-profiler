//go:build !nocgo && !withcgo

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//nolint:lll
package pprof // import "go.opentelemetry.io/ebpf-profiler/plugins/golabels/integrationtests/pprof"

//go:noinline
func busyFunc() {
}
