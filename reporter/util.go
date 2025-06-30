// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package reporter // import "go.opentelemetry.io/ebpf-profiler/reporter"

import (
	"bufio"
	"io"
	"regexp"

	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"
)

//nolint:lll
var (
	cgroupv2ContainerIDPattern = regexp.MustCompile(`0:.*?:.*?([0-9a-fA-F]{64})(?:\.scope)?(?:/[a-z]+)?$`)
)

// hashString is a helper function for LRUs that use string as a key.
// Xxh3 turned out to be the fastest hash function for strings in the FreeLRU benchmarks.
// It was only outperformed by the AES hash function, which is implemented in Plan9 assembly.
func hashString(s string) uint32 {
	return uint32(xxh3.HashString(s))
}

// extractContainerID returns the containerID for pid if cgroup v2 is used.
func extractContainerID(pidCgroupFile io.Reader) string {
	scanner := bufio.NewScanner(pidCgroupFile)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)
	var pathParts []string
	for scanner.Scan() {
		line := scanner.Text()
		pathParts = cgroupv2ContainerIDPattern.FindStringSubmatch(line)
		if pathParts == nil {
			log.Debugf("Could not extract cgroupv2 path from line: %s", line)
			continue
		}
		return pathParts[1]
	}

	// No container ID could be extracted
	return ""
}
