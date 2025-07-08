// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"fmt"
	"math/rand"
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
	labels := pprof.Labels(
		"l1", "label1"+randomString(16),
		"l2", "label2"+randomString(24),
		"l3", "label3"+randomString(48))
	lastUpdate := time.Now()
	pprof.Do(context.TODO(), labels, func(context.Context) {
		for time.Since(lastUpdate) < 10*time.Second {
			// CPU go burr on purpose.
		}
	})
	fmt.Println("PASS")
}
