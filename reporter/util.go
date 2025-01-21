// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import "github.com/zeebo/xxh3"

// hashString is a helper function for LRUs that use string as a key.
// Xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}
