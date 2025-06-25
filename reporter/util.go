// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"regexp"

	"github.com/zeebo/xxh3"
)

var (
	// `([0-9a-fA-F]+)`      : This is the main capturing group. It greedily matches
	//                         one or more hexadecimal characters (0-9, a-f, A-F).
	//                         This will capture the full hash regardless of its length.
	// `(?:\.scope)?`        : Non-capturing group that optionally matches the literal
	//                         ".scope" suffix.
	// `$`                   : Anchors the match to the end of the line.
	// This regex effectively finds the last hexadecimal string right before the end
	// of the line, optionally suffixed with ".scope".
	containerIDRegex = regexp.MustCompile(`([0-9a-fA-F]+)(?:\.scope)?$`)
)

// hashString is a helper function for LRUs that use string as a key.
// Xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

// extractContainerID extracts the container ID from a cgroup v2 path or
// returns an empty string otherwise.
func extractContainerID(cgroupv2Path string) string {
	matches := containerIDRegex.FindStringSubmatch(cgroupv2Path)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
