// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

//go:build nocgo
// +build nocgo

package main

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"runtime/pprof"
	"time"
)

//nolint:gosec
func randomString(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	s := make([]rune, n)
	for i := range s {
		s[i] = letters[rand.Intn(len(letters))]
	}
	return string(s)
}

// This is a normal main program that when go build will be statically linked, this is required
// to work with qemu/bluebox testing harness. A statically linked go test built binary doesn't
// work with the go labels extractor ebpf program, not sure yet if this is a bug.
func main() {
	// If first isn't subtest then we're running via bluebox init and should just exit.
	if len(os.Args) != 3 || os.Args[1] != "-subtest" {
		fmt.Println("PASS")
		return
	}
	cookie := os.Args[2]
	labels := pprof.Labels(
		"l1"+cookie, "label1"+randomString(16),
		"l2"+cookie, "label2"+randomString(24),
		"l3"+cookie, "label3"+randomString(48))
	lastUpdate := time.Now()
	pprof.Do(context.TODO(), labels, func(context.Context) {
		//nolint:revive
		for time.Since(lastUpdate) < 10*time.Second {
			// CPU go burr on purpose.
		}
	})
	fmt.Println("PASS")
}
