//go:build !nocgo && !withcgo

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//nolint:lll
package integrationtests // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels/integrationtests"

//go:noinline
func busyFunc() {
}
