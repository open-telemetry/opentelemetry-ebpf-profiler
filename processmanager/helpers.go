// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package processmanager // import "go.opentelemetry.io/ebpf-profiler/processmanager"

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"regexp"

	log "github.com/sirupsen/logrus"

	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
)

//nolint:lll
var (
	cgroupv2ContainerIDPattern = regexp.MustCompile(`0:.*?:.*?([0-9a-fA-F]{64})(?:\.scope)?(?:/[a-z]+)?$`)
)

// executableReporterStub is a stub to implement reporter.ExecutableReporter which is used
// as the reporter by default. This can be overridden on at processmanager creation time.
type executableReporterStub struct {
}

// ReportExecutable satisfies the reporter.ExecutableReporter interface.
func (er executableReporterStub) ReportExecutable(args *reporter.ExecutableMetadata) {
}

var _ reporter.ExecutableReporter = executableReporterStub{}

// parseContainerID parses cgroup v2 container IDs
func parseContainerID(cgroupFile io.Reader) string {
	scanner := bufio.NewScanner(cgroupFile)
	buf := make([]byte, 512)
	// Providing a predefined buffer overrides the internal buffer that Scanner uses (4096 bytes).
	// We can do that and also set a maximum allocation size on the following call.
	// With a maximum of 4096 characters path in the kernel, 8192 should be fine here. We don't
	// expect lines in /proc/<PID>/cgroup to be longer than that.
	scanner.Buffer(buf, 8192)
	var pathParts []string
	for scanner.Scan() {
		b := scanner.Bytes()
		if bytes.Equal(b, []byte("0::/")) {
			continue // Skip a common case
		}
		line := string(b)
		pathParts = cgroupv2ContainerIDPattern.FindStringSubmatch(line)
		if pathParts == nil {
			log.Debugf("Could not extract cgroupv2 path from line: %s", line)
			continue
		}
		return pathParts[1]
	}

	// No containerID could be extracted
	return ""
}

// extractContainerID returns the containerID for pid if cgroup v2 is used.
func extractContainerID(pid libpf.PID) (string, error) {
	cgroupFile, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}

	return parseContainerID(cgroupFile), nil
}
