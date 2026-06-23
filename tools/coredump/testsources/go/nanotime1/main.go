// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import "time"

func main() {
	start := time.Now()
	for {
		_ = time.Since(start)
	}
}
