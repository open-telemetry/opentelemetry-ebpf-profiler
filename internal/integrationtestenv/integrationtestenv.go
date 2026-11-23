// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package integrationtestenv initializes the environment for the integration
// test binaries. It reduces the kernel console loglevel so kernel messages
// cannot interleave with the test output on the serial console, where they
// can corrupt the markers run-tests.sh counts to determine the test result.
// Every integration test binary blank-imports this package to quiet the
// console before producing any output, in any execution order.
package integrationtestenv // import "go.opentelemetry.io/ebpf-profiler/internal/integrationtestenv"

import (
	"fmt"
	"os"
)

// consoleLoglevel keeps errors and emergencies on the console and drops the
// informational messages that would interleave with the test output.
const consoleLoglevel = "4"

func init() {
	if err := os.WriteFile("/proc/sys/kernel/printk", []byte(consoleLoglevel), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "failed to reduce kernel console loglevel:", err)
	}
}
