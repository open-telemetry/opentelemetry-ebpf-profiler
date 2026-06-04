// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime"
)

func main() {
	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()

	pcs := make([]uintptr, 32)
	for {
		runtime.Callers(0, pcs)
	}
}
