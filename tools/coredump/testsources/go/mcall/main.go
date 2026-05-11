// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Program mcall exercises the runtime.mcall path by parking goroutines
// through various blocking primitives (channels, mutexes, select, sleep)
// and cooperative preemption on deep stacks. A coredump taken while it
// runs is likely to contain threads mid-mcall.
//
// Build: go build -o mcall ./tools/coredump/testsources/go/mcall/
// Run:   ./mcall   (prints PID, then blocks forever — use gcore to dump)
package main

import (
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"
)

//go:noinline
func deepStack(depth int) int {
	if depth <= 0 {
		runtime.Gosched()
		return 0
	}
	return deepStack(depth-1) + 1
}

//go:noinline
func chanBlocker(ch <-chan struct{}) {
	<-ch
}

//go:noinline
func mutexBlocker(mu *sync.Mutex, done <-chan struct{}) {
	for {
		mu.Lock()
		mu.Unlock()
		select {
		case <-done:
			return
		default:
		}
	}
}

//go:noinline
func sleeper() {
	time.Sleep(time.Hour)
}

//go:noinline
func selectBlocker(ch1, ch2 <-chan struct{}) {
	select {
	case <-ch1:
	case <-ch2:
	}
}

func main() {
	fmt.Println("PID:", os.Getpid())
	fmt.Println("Waiting for gcore... (Ctrl+C to stop)")

	done := make(chan struct{})
	neverClose := make(chan struct{})
	var mu sync.Mutex

	// mcall via park_m: channel receive blocks.
	for i := 0; i < 4; i++ {
		go chanBlocker(neverClose)
	}

	// mcall via park_m: select blocks.
	go selectBlocker(neverClose, neverClose)

	// mcall via park_m: time.Sleep blocks.
	for i := 0; i < 2; i++ {
		go sleeper()
	}

	// mcall via gopreempt_m: cooperative yields on deep stacks.
	for i := 0; i < 4; i++ {
		go func() {
			for {
				deepStack(64)
				select {
				case <-done:
					return
				default:
				}
			}
		}()
	}

	// mcall via various paths: mutex contention.
	mu.Lock()
	for i := 0; i < 2; i++ {
		go mutexBlocker(&mu, done)
	}
	mu.Unlock()

	// Block main forever (mcall via park_m).
	<-neverClose
}
