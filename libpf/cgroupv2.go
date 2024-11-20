// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"bufio"
	"fmt"
	"os"
	"regexp"

	lru "github.com/elastic/go-freelru"
	log "github.com/sirupsen/logrus"
)

var (
	cgroupv2PathPattern = regexp.MustCompile(`0:.*?:(.*)`)
)

// LookupCgroupv2 returns the cgroupv2 ID for pid.
func LookupCgroupv2(cgrouplru *lru.SyncedLRU[PID, string], pid PID) (string, error) {
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

	var genericCgroupv2 string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)
	var pathParts []string
	for scanner.Scan() {
		line := scanner.Text()
		pathParts = cgroupv2PathPattern.FindStringSubmatch(line)
		if pathParts == nil {
			log.Debugf("Could not extract cgroupv2 path from line: %s", line)
			continue
		}
		genericCgroupv2 = pathParts[1]
		break
	}

	// Cache the cgroupv2 information.
	// To avoid busy lookups, also empty cgroupv2 information is cached.
	cgrouplru.Add(pid, genericCgroupv2)

	return genericCgroupv2, nil
}
