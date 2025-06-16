// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package libpf // import "go.opentelemetry.io/ebpf-profiler/libpf"

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"

	lru "github.com/elastic/go-freelru"
)

var (
	// `([0-9a-fA-F]+)`       : This is the main capturing group. It greedily matches
	//                         one or more hexadecimal characters (0-9, a-f, A-F).
	//                         This will capture the full hash regardless of its length.
	// `(?:\.scope)?`        : Non-capturing group that optionally matches the literal
	//                         ".scope" suffix.
	// `$`                   : Anchors the match to the end of the line.
	// This regex effectively finds the last hexadecimal string right before the end
	// of the line, optionally preceded by ".scope".
	containerIDRegex = regexp.MustCompile(`([0-9a-fA-F]+)(?:\.scope)?$`)

	errNoMatch = errors.New("could not find a valid container ID")
)

// LookupContainerIDFromCgroup returns the container ID for a PID.
func LookupContainerIDFromCgroup(containerIDs *lru.SyncedLRU[PID, string],
	pid PID) (string, error) {
	id, ok := containerIDs.Get(pid)
	if ok {
		return id, nil
	}

	// Slow path
	f, err := os.Open(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", err
	}
	defer f.Close()

	containerID, err := extractContainerID(f)
	if err != nil {
		return "", err
	}

	// Cache the container ID information.
	// To avoid busy lookups, also empty container ID information is cached.
	containerIDs.Add(pid, containerID)

	return containerID, nil
}

func extractContainerID(f *os.File) (string, error) {
	scanner := bufio.NewScanner(f)
	var extractedID string

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "kubepods") {
			continue
		}
		matches := containerIDRegex.FindStringSubmatch(line)
		if len(matches) > 1 {
			extractedID = matches[1]
			break
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading file: %w", err)
	}

	if extractedID == "" {
		return "", errNoMatch
	}

	return extractedID, nil
}
