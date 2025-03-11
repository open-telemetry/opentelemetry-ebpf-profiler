// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"regexp"

	lru "github.com/elastic/go-freelru"
)

// LookupCgroupv2 returns the cgroupv2 ID for pid.
func LookupCgroupv2(cgrouplru lru.Cache[PID, string], pid PID) (string, error) {
	id, ok := cgrouplru.Get(pid)
	if ok {
		return id, nil
	}

	// Slow path
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	return LookupCgroupFromReader(cgrouplru, pid, f)
}

func LookupCgroupFromReader(
	cgrouplru lru.Cache[PID, string],
	pid PID,
	f io.Reader,
) (string, error) {
	var genericCgroupv2 string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)
	for scanner.Scan() {
		line := scanner.Text()
		genericCgroupv2 = getContainerIDFromCGroup(line)
		if genericCgroupv2 == "" {
			continue
		}
		break
	}

	// Cache the cgroupv2 information.
	// To avoid busy lookups, also empty cgroupv2 information is cached.
	cgrouplru.Add(pid, genericCgroupv2)

	return genericCgroupv2, nil
}

var (
	// cgroupContainerIDRe matches a container ID from a /proc/{pid}}/cgroup
	cgroupContainerIDRe = regexp.MustCompile(`^.*/(?:.*-)?([0-9a-f]{64})(?:\.|\s*$)`)
)

func getContainerIDFromCGroup(line string) string {
	matches := cgroupContainerIDRe.FindStringSubmatch(line)
	if len(matches) <= 1 {
		return ""
	}
	return matches[1]
}
