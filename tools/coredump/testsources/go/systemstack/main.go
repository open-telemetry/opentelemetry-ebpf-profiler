// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"runtime"
	"runtime/pprof"
	"time"
)

func main() {
	f, err := os.Create("cpu.pprof")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()

	pcs := make([]uintptr, 32)
	deadline := time.After(30 * time.Second)
	for {
		select {
		case <-deadline:
			return
		default:
			runtime.Callers(0, pcs)
		}
	}
}
