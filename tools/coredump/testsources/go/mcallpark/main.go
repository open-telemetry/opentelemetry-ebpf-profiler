// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"runtime"
	"time"
)

//go:noinline
func parker(ch <-chan struct{}) {
	<-ch
}

func main() {
	runtime.GOMAXPROCS(8)
	fmt.Println("PID:", os.Getpid())

	ch := make(chan struct{})
	for i := 0; i < 8; i++ {
		go parker(ch)
	}
	time.Sleep(time.Hour)
}

