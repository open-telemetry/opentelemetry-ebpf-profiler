// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Exercise the post-dropg mcall case where the candidate goroutine found from
// the g0 stack has already been rescheduled on another M. In that state, stopping
// at runtime.mcall is safer than reading a potentially stale gobuf.
package main

import (
	"fmt"
	"os"
	"runtime"
)

//go:noinline
func yielder() {
	for {
		runtime.Gosched()
	}
}

func main() {
	fmt.Println("PID:", os.Getpid())
	for i := 0; i < 16; i++ {
		go yielder()
	}
	select {}
}
