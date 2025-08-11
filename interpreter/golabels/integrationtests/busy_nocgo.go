//go:build nocgo && linux

// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package integrationtests // import "go.opentelemetry.io/ebpf-profiler/interpreter/golabels/integrationtests"

//go:noinline
func busyFunc() {
}
