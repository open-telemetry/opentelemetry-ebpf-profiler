/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Apache License 2.0.
 * See the file "LICENSE" for details.
 */

package host

import (
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/otel-profiling-agent/config"
	"github.com/elastic/otel-profiling-agent/libpf"
)

const (
	tags          = "foo;bar;this-tag-should-be-dropped-!;baz;1.2.3.4;key:value;a_b_c"
	validatedTags = "foo;bar;baz;1.2.3.4;key:value;a_b_c"
)

func TestValidateTags(t *testing.T) {
	tests := map[string]string{
		tags: validatedTags,
		"":   "",
	}

	for testTags, testValidatedTags := range tests {
		vTags := ValidateTags(testTags)
		if vTags != testValidatedTags {
			t.Errorf("validated tags %s != %s", vTags, testValidatedTags)
		}
	}
}

func TestAddMetadata(t *testing.T) {
	err := config.SetConfiguration(&config.Config{
		ProjectID:      42,
		CacheDirectory: ".",
		SecretToken:    "secret",
		ValidatedTags:  validatedTags})
	if err != nil {
		t.Fatalf("failed to set temporary config: %s", err)
	}

	// This tests checks that common metadata keys are populated
	metadataMap := make(map[string]string)

	// Ignore errors because collection may fail in unit tests. However, we check the contents of
	// the returned map, which ensures test coverage.
	_ = AddMetadata("localhost:12345", metadataMap)
	expectedHostname, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	actualHostname, found := metadataMap[KeyHostname]
	if !found {
		t.Fatalf("no hostname found")
	}
	if actualHostname != expectedHostname {
		t.Fatalf("wrong hostname, expected %v, got %v", expectedHostname, actualHostname)
	}

	tags, found := metadataMap[keyTags]
	if !found {
		t.Fatalf("no tags found")
	}

	if tags != validatedTags {
		t.Fatalf("added tags '%s' != validated tags '%s'", tags, validatedTags)
	}

	ip, found := metadataMap[KeyIPAddress]
	if !found {
		t.Fatalf("no IP address")
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		t.Fatalf("got a nil IP address")
	}

	procVersion, found := metadataMap[KeyKernelProcVersion]
	if !found {
		t.Fatalf("no kernel_proc_version")
	}

	expectedProcVersion, err := os.ReadFile("/proc/version")
	if err != nil {
		t.Fatal(err)
	}
	if procVersion != sanitizeString(expectedProcVersion) {
		t.Fatalf("wrong kernel_proc_version, expected %v, got %v", procVersion, expectedProcVersion)
	}

	_, found = metadataMap[KeyKernelVersion]
	if !found {
		t.Fatalf("no kernel version")
	}

	// The below test for bpf_jit_enable may not be reproducible in all environments, as we may not
	// be able to read the value depending on the capabilities/privileges/network namespace of the
	// test process.
	jitEnabled, found := metadataMap["host:sysctl/net.core.bpf_jit_enable"]

	if found {
		switch jitEnabled {
		case "0", "1", "2":
		default:
			t.Fatalf("unexpected value for sysctl: %v", jitEnabled)
		}
	}

	cacheKey := key(keyCPUCacheL1d)
	cache, ok := metadataMap[cacheKey]
	assert.True(t, ok)
	assert.NotEmpty(t, cache)

	cacheSockets, ok := metadataMap[keySocketID(cacheKey)]
	assert.True(t, ok)
	assert.NotEmpty(t, cacheSockets)
	assert.True(t, cacheSockets[0] == '0',
		"expected '0' at start of '%v'", cacheSockets)
	sids := strings.Split(cacheSockets, ",")
	socketIDs := libpf.MapSlice(sids, func(a string) int {
		n, _ := strconv.Atoi(a)
		return n
	})
	assert.True(t, sort.IntsAreSorted(socketIDs),
		"expected '%v' to be numerically sorted", sids)
}
