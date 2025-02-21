package discovery

import (
	"regexp"
)

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
